apt-get -qqy update
apt-get -qqy upgrade
apt-get -qqy install make zip unzip postgresql
apt-get -qqy install python3 python3-pip
pip3 install --upgrade pip
pip3 install flask packaging oauth2client redis passlib flask-httpauth
pip3 install sqlalchemy flask-sqlalchemy psycopg2 bleach
apt-get -qqy install python python-pip
pip2 install --upgrade pip
pip2 install flask packaging oauth2client redis passlib flask-httpauth
pip2 install sqlalchemy flask-sqlalchemy psycopg2 bleach
su postgres -c 'createuser -dRS grader'
su grader -c 'createdb itemcatalog'
echo "Done installing!"