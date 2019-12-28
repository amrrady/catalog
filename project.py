#!/usr/bin/env python3

from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import random
import string
import json
import requests

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"


# Connect to Database and create database session
engine = create_engine('sqlite:///categorylistwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

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
    except BaseException:
        return None


# Create an anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


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
        oauth_flow = flow_from_clientsecrets(
            'google_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = 'https://www.googleapis.com/oauth2'
    url += '/v2/tokeninfo?access_token={}'.format(access_token)
    result = requests.get(url).json()
    # If there was an error in the access token info, abort.
    if 'error' in result:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    google_id = credentials.id_token['sub']
    if result['user_id'] != google_id:
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
    stored_google_id = login_session.get('google_id')
    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['google_id'] = google_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        flash('Current user not connected.')
        return redirect(url_for('showCategories'))

    result = requests.get(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': access_token},
        headers={'content-type': 'application/x-www-form-urlencoded'})
    tokenExpired = (('error_description' in result.json()) and 
        (result.json()['error_description'] == 'Token expired or revoked'))

    if((result.status_code == 200) or tokenExpired):
        disconnect()
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


def disconnect():
    del login_session['google_id']
    del login_session['access_token']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']


# Show all categories
@app.route('/')
@app.route('/catalog/')
@app.route('/category/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    enableEdit = True
    if 'username' not in login_session:
        enableEdit = False
    return render_template(
        'categories.html',
        categories=categories,
        enableEdit=enableEdit)

# Create a new category


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category {} Successfully Created'.format(newCategory.name))
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')

# Edit a category


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    categoryToEdit = session.query(Category).filter_by(
        id=category_id).one()
    if (('username' not in login_session) or
            categoryToEdit.user_id != login_session['user_id']):
        return redirect('/login')

    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
            flash(
                'Category {} Successfully Edited'.format(
                    categoryToEdit.name))
            return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=categoryToEdit)


# Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if (('username' not in login_session) or
            (categoryToDelete.user_id != login_session['user_id'])):
        return redirect('/login')

    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash('{} Successfully Deleted'.format(categoryToDelete.name))
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        return render_template(
            'deleteCategory.html',
            category=categoryToDelete)


# Show a category list

@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/list/')
def showCategoryList(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(CategoryItem).filter_by(
        category_id=category_id).all()
    enableEdit = True
    if (('username' not in login_session) or
            (creator.id != login_session['user_id'])):
        enableEdit = False
    return render_template('categoryList.html', items=items, category=category,
                           creator=creator, enableEdit=enableEdit)


# Create a new category list item
@app.route('/category/<int:category_id>/list/new/', methods=['GET', 'POST'])
def newCategoryListItem(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if (('username' not in login_session) or
            (category.user_id != login_session['user_id'])):
        return redirect('/login')

    if request.method == 'POST':
        newItem = CategoryItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_id=category.user_id)
        session.add(newItem)
        session.commit()
        flash('New Catrory %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCategoryList', category_id=category_id))
    else:
        return render_template(
            'newCategoryListItem.html',
            category_id=category_id)

# Edit a category list item


@app.route(
    '/category/<int:category_id>/list/<int:item_id>/edit',
    methods=[
        'GET',
        'POST'])
def editCategoryListItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if (('username' not in login_session) or
            (category.user_id != login_session['user_id'])):
        return redirect('/login')

    itemToEdit = session.query(CategoryItem).filter_by(id=item_id).one()

    if request.method == 'POST':
        if request.form['name']:
            itemToEdit.name = request.form['name']
        if request.form['description']:
            itemToEdit.description = request.form['description']
        session.add(itemToEdit)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showCategoryList', category_id=category_id))
    else:
        return render_template(
            'editCategoryListItem.html',
            category_id=category_id,
            item_id=item_id,
            item=itemToEdit)


# Delete a category list item
@app.route(
    '/category/<int:category_id>/list/<int:item_id>/delete',
    methods=[
        'GET',
        'POST'])
def deleteCategoryListItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if (('username' not in login_session) or
            (category.user_id != login_session['user_id'])):
        return redirect('/login')
    itemToDelete = session.query(CategoryItem).filter_by(id=item_id).one()

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategoryList', category_id=category_id))
    else:
        return render_template(
            'deleteCategoryListItem.html',
            category_id=category_id,
            item=itemToDelete)


# JSON APIs to view Cateories Information
@app.route('/category/<int:category_id>/list/JSON')
def categoryListJSON(category_id):
    items = session.query(CategoryItem).filter_by(
        category_id=category_id).all()
    return jsonify(CategoryItem=[i.serialize for i in items])


@app.route('/category/<int:category_id>/list/<int:item_id>/JSON')
def categoryItemJSON(category_id, item_id):
    item = session.query(CategoryItem).filter_by(id=item_id).one()
    return jsonify(CategoryItem=item.serialize)


@app.route('/category/JSON')
def categoryJSON():
    items = session.query(Category).all()
    return jsonify(restaurants=[i.serialize for i in items])


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
