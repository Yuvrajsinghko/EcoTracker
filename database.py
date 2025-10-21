from pymysql.cursors import DictCursor
from pymysql.constants import CLIENT
from dbutils.pooled_db import PooledDB
import pymysql

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'yuvraj',
    'password': 'root69',
    'database': 'greendb',
    'cursorclass': DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS,
}

# Create a connection pool
pool = PooledDB(
    creator=pymysql,
    maxconnections=20,  # Maximum number of connections
    mincached=5,        # Minimum number of cached connections
    maxcached=10,       # Maximum number of cached connections
    maxshared=3,        # Maximum number of shared connections
    blocking=True,      # Block when no connection is available
    **DB_CONFIG
)

def get_db():
    """Get a database connection from the pool"""
    return pool.connection()