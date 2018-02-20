#!/usr/local/bin/python
# -*- coding: utf-8 -*-
from functools import wraps
from flask import Flask, render_template, request, redirect, jsonify
from flask import url_for, flash

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# import logging
# LOG_FILENAME = 'pylogfile.log'
# logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/html/catalog/client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Connect to Database and create database session
#engine = create_engine('sqlite:///itemcatalog.db')
engine = create_engine('postgresql://grader:grader@localhost:5432/grader')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

categories = session.query(Category).order_by(asc(Category.name))


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, categories=categories)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        print 'Invalid state parameter'
        return response
    # Obtain authorization code
    access_token = request.data

    app_id = json.loads(
        open('/var/www/html/catalog/fb_client_secrets.json','r').read())['web']['app_id']
    app_secret = json.loads(
        open('/var/www/html/catalog/fb_client_secrets.json','r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    # logging.debug(url)
    result = h.request(url, 'GET')[1]
    # logging.debug(result)
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # logging.debug("url sent for API access:%s"% url)
    # logging.debug("API JSON result: %s" % result)
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px; -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

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
        oauth_flow = flow_from_clientsecrets('/var/www/html/catalog/client_secret.json', scope='')
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

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
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
    output += ' " style = "width: 300px; height: 300px;\
    border-radius: 150px;-webkit-border-radius: 150px;\
    -moz-border-radius: 150px;"> '
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


def isUserCreator(user_id):
    creator = getUserInfo(user_id)
    if creator.id == login_session['user_id']:
        return True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    # logging.debug('In gdisconnect access token is %s', access_token)
    # logging.debug('User name is: ')
    # logging.debug(login_session['username'])
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    # logging.debug(url)
    result = h.request(url, 'GET')[0]
    # logging.debug(h.request(url, 'GET'))
    # logging.debug('result is ')
    # logging.debug(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
	# logging.debug(response)
	# logging.debug('200: All data user deleted')
        return response
    else:
        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400))
        response.headers['Content-Type'] = 'application/json'
	# logging.debug(response)
	# logging.debug('something weird happend, check the code.')
        return response


@app.route('/')
@app.route('/catalog/')
def showLatestItems():
    """
    showLatestItems: show the latest items of all categories

    Returns:
        return the rendered template
    """
    latestItems = session.query(Item).order_by(
        desc(Item.id)).all()
    if 'username' not in login_session:
        return render_template('publiclatestitems.html',
                               categories=categories, latest_items=latestItems)
    else:
        return render_template(
            'latestitems.html',
            categories=categories,
            latest_items=latestItems)


@app.route('/catalog/<string:category_name>/items')
def showCategoryItems(category_name):
    """
    showCategoryItems: show all items from a category

    Args:
        category_name (string): name of the category

    Returns:
        return the template rendered
    """
    category = session.query(Category).filter_by(name=category_name).first()
    categoryItems = session.query(Item).filter_by(
        category_id=category.id).order_by(Item.title)
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session or creator.id != login_session[
            'user_id']:
        return render_template(
            'publiccategoryitems.html',
            categories=categories,
            category_items=categoryItems,
            category_name=category_name)
    else:
        return render_template(
            'categoryitems.html',
            categories=categories,
            category_items=categoryItems,
            category_name=category_name)


@app.route('/catalog/<string:category_name>/<string:item_title>')
def showCatalogItem(category_name, item_title):
    """
    showCatalogItem: show a specific item from the catalog

    Args:
        category_name (string): name of the category
        item_title (string): title of the item

    Returns:
        return the template rendered
    """
    catalogItem = session.query(Item).filter_by(
        title=item_title).first()
    creator = getUserInfo(catalogItem.user_id)
    if 'username' not in login_session or creator.id != login_session[
            'user_id']:
        return render_template('publiccatalogitem.html', item=catalogItem)
    else:
        return render_template('catalogitem.html', item=catalogItem)


@app.route('/catalog/category/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    newCategory: method to create a new category

    Returns:
        return the template rendered
    """
    if request.method == 'POST':
        name = request.form['name']
        category = session.query(Category).filter_by(name=name).all()
        if category:
            flash('Name of the category already exists. Try another name please.')
            return render_template('newcategory.html', categories=categories)
        else:
            newCategory = Category(name=name, user_id=login_session['user_id'])
            session.add(newCategory)
            session.commit()
            flash('New Category %s Successfully Created' % newCategory.name)
            return redirect(url_for('showLatestItems'))
    else:
        return render_template('newcategory.html', categories=categories)


@app.route('/catalog/category/<string:category_name>/edit',
           methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    """
    editCategory: method to edit a specific category

    Args:
        category_name (string): name of the category

    Returns:
        return the remplate rendered or redirect to showLatestItems
    """
    editedCategory = session.query(
        Category).filter_by(name=category_name).first()
    if not isUserCreator(editedCategory.user_id):
        flash('You are not the creator of this category')
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
        return redirect(url_for('showLatestItems'))
    else:
        return render_template('editcategory.html',
                               categories=categories, category=editedCategory)


@app.route('/catalog/category/<string:category_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    """
    deleteCategory: method to delete a specific category

    Args:
        category_name (string): name of the category

    Returns:
        return the template rendered of redirects to showLatestItems
    """
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).first()
    if not isUserCreator(categoryToDelete.user_id):
        flash('You are not the creator of this category')
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showLatestItems'))
    else:
        return render_template(
            'deletecategory.html',
            categories=categories,
            restaurant=categoryToDelete)


@app.route('/catalog/item/new', methods=['GET', 'POST'])
@login_required
def newCatalogItem():
    """
    newCatalogItem: method to create a new catalog item

    Returns:
        return the template rendered or redirect to showCatalogItem
    """
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            id=request.form['category']).one()
        title = request.form['title']
        catalogItem = session.query(Item).filter_by(title=title).all()
        if catalogItem:
            flash('Title of the item already exists.\
             Try another title please.')
            return render_template('newcatalogitem.html',
                                   categories=categories)
        else:
            newItem = Item(
                title=request.form['title'],
                description=request.form['description'],
                category_id=category.id,
                user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New Catalog %s Item Successfully Created' % (newItem.title))
            return redirect(
                url_for(
                    'showCatalogItem',
                    category_name=category.name,
                    item_title=newItem.title))
    else:
        return render_template('newcatalogitem.html', categories=categories)


@app.route('/catalog/item/<string:item_title>/edit', methods=['GET', 'POST'])
@login_required
def editCatalogItem(item_title):
    """
    editCatalogItem: method to edit an specific item of the catalog

    Args:
        item_title (string): title of the item

    Returns:
        return the template rendered or redirect to showCategoryItems
    """
    editedItem = session.query(Item).filter_by(title=item_title).first()
    category = session.query(Category).filter_by(
        id=editedItem.category_id).one()
    if not isUserCreator(editedItem.user_id):
        flash('You are not the creator of this item')
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_id = request.form['category']
        session.add(editedItem)
        session.commit()
        flash('Catalog Item Successfully Edited')
        return redirect(url_for('showCategoryItems',
                                category_name=category.name))
    else:
        return render_template('editcatalogitem.html',
                               categories=categories, item=editedItem)


@app.route('/catalog/item/<string:item_title>/delete', methods=['GET', 'POST'])
@login_required
def deleteCatalogItem(item_title):
    """
    deleteCatalogItem: method to delete a specific item of the catalog

    Args:
        item_title (string): title of the item

    Returns:
        return the template rendered of redirect to showCategoryItems
    """
    itemToDelete = session.query(
        Item).filter_by(title=item_title).first()
    category = session.query(Category).filter_by(
        id=itemToDelete.category_id).first()
    if not isUserCreator(itemToDelete.user_id):
        flash('You are not the creator of this item')
        return redirect(url_for('showLatestItems'))
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Catalog Item Successfully Deleted')
        return redirect(url_for('showCategoryItems',
                                category_name=category.name))
    else:
        return render_template('deletecatalogitem.html', item=itemToDelete)


@app.route('/catalog.json')
def catalogJSON():
    """
    catalogJSON: method to show the structure of the catalog in JSON

    Returns:
        return a JSON of the catalog categories and items
    """
    result = []
    categories = session.query(Category).all()
    for category in categories:
        items = session.query(Item).filter_by(
            category_id=category.id).all()
        currentCategory = {}
        currentCategory['id'] = category.id
        currentCategory['name'] = category.name
        if items:
            currentCategory['items'] = [i.serialize for i in items]
        result.append(currentCategory)
    return jsonify(Category=result)


@app.route('/catalog/<string:item_title>/item.json')
def catalogItemJSON(item_title):
    """
    catalogItemJSON: method to show a specific catalog item in JSON

    Args:
        item_title (string): title of the catalog item

    Returns:
        return a JSON of the item
    """
    item = session.query(Item).filter_by(title=item_title).one()
    return jsonify(Item=item.serialize)


@app.route('/disconnect')
def disconnect():
    """
    disconnect: method to disconnect the current user logged in

    Returns:
        return redirect to showLatestItems
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLatestItems'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showLatestItems'))

if __name__ == '__main__':
    app.secret_key = 'mega_secret_key'
    app.debug = False
    app.run(host='0.0.0.0', port=5002)
