from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, MenuItem, User

engine = create_engine('sqlite:///catalogwithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/' +
             '18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()


catalog1 = Catalog(user_id=1, name="Football")

session.add(catalog1)
session.commit()

menuItem1 = MenuItem(user_id=1, name="Jersey",
                     description="Jersey for playing Football",
                     price="$7.50", catalog=catalog1)

session.add(menuItem1)
session.commit()

catalog2 = Catalog(user_id=1, name="Cricket")

session.add(catalog1)
session.commit()

menuItem1 = MenuItem(user_id=1, name="Bat", description="Made of high quality",
                     price="$15.00", catalog=catalog2)

session.add(menuItem1)
session.commit()


print "items added!"
