from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Catalog, Base, MenuItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token

@app.route('/login')
def showLogin():
    """ Creating and redirecting to loging page"""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    # Exchange client token for long-lived server-side token
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/v2.9/oauth/access_token?'
           'grant_type=fb_exchange_token&client_id=%s&client_secret=%s'
           '&fb_exchange_token=%s') % (app_id, app_secret, access_token)
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API.
    url = 'https://graph.facebook.com/v2.9/me?%s&fields=name,id,email' % token
    http = httplib2.Http()
    result = http.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&' +\
        'redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    print(data)
    # login_session['picture'] = data["data"]["url"]
    login_session['picture'] = "xyz"

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:' +\
        ' 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already ' +
                                            'connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:' +\
        ' 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# JSON APIs to view Catalog Information


@app.route('/catalog.json')
def catalogSON():
    items = session.query(MenuItem).filter_by(
        catalog_id=catalog_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])
    catalogs = session.query(Catalog).all()
    return jsonify(Catalog=[r.serialize for r in catalogs])


@app.route('/catalog/<int:catalog_id>/JSON')
def catalogItemJSON(catalog_id):
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(MenuItem).filter_by(
        catalog_id=catalog_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# Show all Catalogs
@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    """Full Catalog and Item details"""
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    catalogUniqueName = session.query(Catalog.name).distinct()
    menuItems = session.query(MenuItem).order_by(asc(MenuItem.name))
    if 'username' not in login_session:
        return render_template('publiccatalogs.html',
                               catalogs=catalogs,
                               catalogUniqueName=catalogUniqueName,
                               items=menuItems)
    else:
        return render_template('catalogs.html',
                               catalogs=catalogs,
                               catalogUniqueName=catalogUniqueName,
                               items=menuItems)

# Show a catalog items


@app.route('/catalog/<string:catalog_name>/')
@app.route('/catalog/<string:catalog_name>/item/')
def showCateg(catalog_name):
    """ Item corresponding to  Catalog (category)"""
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    catalogUniqueName = session.query(Catalog.name).distinct()
    catalog = session.query(Catalog).filter_by(name=catalog_name)

    items = session.query(MenuItem).order_by(asc(MenuItem.name)).all()


    return render_template('publicCategoriesItem.html',
                           items=items, catalogs=catalog,
                           catalogUniqueName=catalogUniqueName)



# Show Item Description


@app.route('/catalog/<string:catalog_name>/<string:item_name>/item/')
def showItem(catalog_name, item_name):
    """Show item and description corresponding to catalog (category)"""
    catalogs = session.query(Catalog).filter_by(name=catalog_name)
    item = session.query(MenuItem).filter_by(name=item_name)
    for cat in catalogs:
        if cat.name == catalog_name:
            for i in item:
                if i.catalog_id == cat.id:
                    if i.name == item_name:
                        catalog_id = i.catalog_id
                        item_id = i.id
                        user = i.user_id

    creator = getUserInfo(user)
    item = session.query(MenuItem).filter_by(
        id=item_id).one()
    if 'username' not in login_session or creator.id != login_session[
            'user_id']:
        return render_template('publicitem.html', item=item)
    else:
        return render_template('item.html', item=item)

# Create a new menu item


@app.route('/catalog/item/new', methods=['GET', 'POST'])
def newItem():
    """ Adding new idem and catalog (if catalog for user doesnot exist)"""
    if 'username' not in login_session:
        return redirect('/login')

    catalogs = session.query(Catalog).order_by(asc(Catalog.name))

    catalogUnique = session.query(Catalog.name).distinct()

    if request.method == 'POST':


        catalogUser = session.query(Catalog).filter_by(
            user_id=login_session['user_id'], name=request.form['categories'])

        if catalogUser.count() == 0:
            catItem = Catalog(name=request.form[
                              'categories'], user_id=login_session['user_id'])
            print("______________")
            session.add(catItem)
            session.commit()
        # print(request.form['categories'])
        catalog = session.query(Catalog).filter_by(
            name=request.form['categories'], user_id=login_session['user_id'])
        newItem = MenuItem(name=request.form['title'],
                           description=request.form['description'],
                           price=request.form[
                               'price'], catalog_id=catalog[0].id,
                           user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCateg', catalog_name=catalog[0].name))
    else:
        return render_template('newitem.html', catalogs=catalogUnique)


# Edit a menu item

@app.route('/catalog/<int:catalog_id>/<int:item_id>/<string:item_name>/edit/')
@app.route('/catalog/<string:item_name>/edit/', methods=['GET', 'POST'])
def editItem(item_name, catalog_id, item_id):
    """ Editing item details and updating MenuItem and Catalog table"""
    if 'username' not in login_session:
        return redirect('/login')

    editedItem = session.query(MenuItem).filter_by(id=item_id).one()

    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    catalogUnique = session.query(Catalog.name).distinct()
    if login_session['user_id'] != catalog.user_id:
        return "<script>function myFunction() {alert('You are not " +\
            "authorized to edit this items. Please create your own " +\
            "catalog/item in order to edit items.');}</script><body " +\
            "onload='myFunction()'>"
    if request.method == 'POST':

        catalogUser = session.query(Catalog).filter_by(
            user_id=login_session['user_id'], name=request.form['categories'])

        if catalogUser.count() == 0:
            catItem = Catalog(name=request.form[
                              'categories'], user_id=login_session['user_id'])
            print("______________")
            session.add(catItem)
            session.commit()

        catalogs = session.query(Catalog).order_by(asc(Catalog.name))

        if request.form['title']:
            editedItem.name = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['categories']:
            for cat in catalogs:
                if cat.name == request.form[
                        'categories'] and cat.user_id == login_session[
                        'user_id']:
                    catalog_name = cat.name
                    editedItem.catalog_id = cat.id
                    session.add(editedItem)
                    session.commit()
                    flash('Item Successfully Edited')
                    return redirect(url_for('showCateg',
                                            catalog_name=cat.name))
    else:
        print(catalog.name)
        return render_template('edititem.html',
                               catalog_id=catalog_id, item_id=item_id,
                               item=editedItem, catalog_name=catalog.name,
                               catalogs=catalogUnique)

# Delete an item


@app.route('/catalog/<int:catalog_id>/<int:item_id>/<string:item_name>/' +
           'delete/', methods=['GET', 'POST'])
@app.route('/catalog/<string:item_name>/delete/', methods=['GET', 'POST'])
def deleteItem(item_name, catalog_id, item_id):
    """Deleting item on item id and catalog if no item exist"""
    itemToDelete = session.query(
        MenuItem).filter_by(id=item_id).one()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not " +\
            "authorized to delete this item. Please create your own " +\
            "item in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        flash('%s Successfully Deleted' % itemToDelete.name)
        session.commit()
        return redirect(url_for('showCateg', catalog_name=catalog.name))
    else:
        return render_template('deleteitem.html',
                               item=itemToDelete, catalog_name=catalog.name)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalogs'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalogs'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
