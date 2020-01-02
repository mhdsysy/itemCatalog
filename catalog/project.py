#!/usr/bin/env python3
from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash

from sqlalchemy import exc
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Items, Category

from flask import session as login_session


from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import hashlib
import os

import httplib2
import json
from flask import make_response
import requests

import datetime

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///database.db')
Base.metadata.bind = engine


# JSON
@app.route('/catalog.json')
def catalogJSON():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).all()
    return jsonify(Catalog=[category.serialize for category in categories])


@app.route('/catalog/categories.json')
def categoriesJSON():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/catalog/items.json')
def itemsJSON():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    items = session.query(Items).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<string:categoryName>/items/JSON')
def categoryJSON(categoryName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    category = session.query(Category).filter_by(name=categoryName).one()
    items = session.query(Items).filter_by(category=category).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<string:categoryName>/<string:itemName>/JSON')
def ItemJSON(categoryName, itemName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    category = session.query(Category).filter_by(name=categoryName).one()
    item = session.query(Items).filter_by(name=itemName,
                                          category=category).one()
    return jsonify(item=[item.serialize])


# Create anti forgery state token
@app.route('/login')
def showLogin():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    login_session['isloggedin'] = True

    flash("you are now logged in as %s" % login_session['username'])
    return " "


def createUser(login_session):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except exc.SQLAlchemyError:
       print("No result for the requested query")

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    error = json.loads(h.request(url, 'GET')[1])

    if result['status'] == '200':
        print("in success")
        login_session['isloggedin'] = False
        login_session.pop('username')
        login_session['gplus_id'] = hashlib.sha256(
            os.urandom(1024)).hexdigest()
        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully disconnected ')
        return redirect('/')

    if error['error'] == 'invalid_token':
        print("in error")
        login_session['isloggedin'] = False
        login_session.pop('username')
        login_session['gplus_id'] = hashlib.sha256(
            os.urandom(1024)).hexdigest()
        login_session['gplus_id'] = hashlib.sha256(
            os.urandom(1024)).hexdigest()
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'

        return redirect('/')
    else:
        print("in else")
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        flash('Failed to revoke token for given user.')
        return redirect('/')


@app.route('/')
@app.route('/catalog')
def showCatalog():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    allCategories = session.query(Category).filter(
        (Category.name) != "").order_by(asc(Category.name)).all()
    allitems = session.query(Items).order_by(desc(Items.date_added)).all()

    items = session.query(Items).order_by(desc(Items.date_added)).limit(9)
    nameOfCategories = {}
    if 'username' in login_session:
        login_session['isloggedin'] = True
    else:
        login_session['isloggedin'] = False

    for item in allitems:
        correspondingCategory = session.query(
            Category).filter_by(id=item.category_id).one()
        nameOfCategories[item.name] = correspondingCategory.name

    return render_template('catalog.html', categories=allCategories,
                           items=items, nameOfCategories=nameOfCategories,
                           isloggedin=login_session['isloggedin'])


# Category Items ## check why count and owner are used
@app.route('/catalog/<string:categoryName>/items/')
def showCategory(categoryName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    allCategories = session.query(Category).filter(
        (Category.name) != "").order_by(asc(Category.name)).all()
    category = session.query(Category).filter_by(name=categoryName).one()
    allItems = session.query(Items).filter_by(
        category=category).order_by(asc(Items.name)).all()
    owner = getUserInfo(category.user_id)
    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('itemsPublic.html',
                               category=category.name,
                               categories=allCategories,
                               items=allItems)
    else:
        user = getUserInfo(login_session['user_id'])
        return render_template('items.html',
                               category=category.name,
                               categories=allCategories,
                               items=allItems,
                               user=user)


# Displaying a Specific Item ## rename templates
@app.route('/catalog/<string:categoryName>/<string:itemName>/')
def showItem(categoryName, itemName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    allCategories = session.query(Category).filter(
        (Category.name) != "").order_by(asc(Category.name)).all()
    item = session.query(Items).filter_by(name=itemName).one()
    owner = getUserInfo(item.user_id)

    if 'username' not in login_session or owner.id != login_session['user_id']:
        return render_template('public_itemdetail.html',
                               item=item,
                               category=categoryName,
                               categories=allCategories,
                               owner=owner)
    else:
        return render_template('itemdetail.html',
                               item=item,
                               itemName=itemName,
                               categoryName=categoryName,
                               categories=allCategories,
                               owner=owner)


# Check / rename templates
@app.route('/catalog/newCategory', methods=['GET', 'POST'])
def newCategory():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'],
            user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash('New Category has been successfully Created!')
        return redirect('/')
    else:
        return render_template('addcategory.html')


# Edit a category
@app.route('/catalog/<string:categoryName>/edit', methods=['GET', 'POST'])
def editCategory(categoryName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    categoryToEdit = session.query(Category).filter_by(name=categoryName).one()
    owner = getUserInfo(categoryToEdit.user_id)

    if owner.id != login_session['user_id']:
        flash("""Users can only edit categories which they have created,
                Please try to edit only your own categories""")
        return redirect('/')
    # POST methods
    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
        session.add(categoryToEdit)
        session.commit()
        flash('Category has been Successfully Edited!')
        return redirect('/')
    else:
        return render_template('editcategory.html',
                               category=categoryToEdit)


# Delete a category
@app.route('/catalog/<string:categoryName>/delete', methods=['GET', 'POST'])
def deleteCategory(categoryName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    categoryToDelete = session.query(
        Category).filter_by(name=categoryName).one()
    owner = getUserInfo(categoryToDelete.user_id)
    if owner.id != login_session['user_id']:
        flash("""Users can only edit categories which they have created,
                Please try to edit only your own categories""")
        return redirect('/')
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('Category {} has been Successfully Deleted! '.format(
            categoryToDelete.name))
        return redirect('/')
    else:
        return render_template('deletecategory.html',
                               category=categoryName)


# Add an item
@app.route('/catalog/newItem', methods=['GET', 'POST'])
def newItem():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    categories = session.query(Category).all()
    if request.method == 'POST':
        newItem = Items(
            name=request.form['name'],
            description=request.form['description'],
            category=session.query(Category).filter_by(
                name=request.form['category']).one(),
            date_added=datetime.datetime.now(),
            user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item has been successfully Added!')
        return redirect('/')
    else:
        return render_template('additem.html',
                               categories=categories)


# Edit an item
@app.route('/catalog/<string:categoryName>/<string:itemName>/edit',
           methods=['GET', 'POST'])
def editItem(categoryName, itemName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    itemToEdit = session.query(Items).filter_by(name=itemName).one()
    categoryOfItem = session.query(Category).filter_by(
        id=itemToEdit.category_id).one()
    categories = session.query(Category).all()
    owner = getUserInfo(itemToEdit.user_id)
    if owner.id != login_session['user_id']:
        flash("""Users can only edit Items which they have created,
                Please try to edit only your own categories""")
        return redirect('/')

    if request.method == 'POST':
        if request.form['name']:
            itemToEdit.name = request.form['name']
        if request.form['description']:
            itemToEdit.description = request.form['description']
        if request.form['category']:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            itemToEdit.category = category
        session.add(itemToEdit)
        session.commit()
        flash('Item has been Successfully Edited!')
        return redirect('/')
    else:
        return render_template('edititem.html',
                               categoryName=categoryName,
                               itemName=itemName,
                               item=itemToEdit,
                               category=categoryOfItem,
                               categories=categories)


# Delete an item
@app.route('/catalog/<string:categoryName>/<string:itemName>/delete',
           methods=['GET', 'POST'])
def deleteItem(categoryName, itemName):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()

    itemToDelete = session.query(Items).filter_by(name=itemName).one()
    owner = getUserInfo(itemToDelete.user_id)

    if owner.id != login_session['user_id']:
        flash("""Users can only edit Items which they have created,
                Please try to edit only your own categories""")
        return redirect('/')
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item has been Successfully Deleted!')
        return redirect('/')
    else:
        return render_template('deleteitem.html',
                               item=itemName,
                               category=categoryName)


if __name__ == '__main__':
    app.secret_key = 'Super_Secret_Key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
