import sys, os
from unittest.mock import MagicMock, patch
import pytest
import pymysql

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import app as flask_app, db as database


@pytest.fixture()
def app():
    """A fixture to create and configure a test Flask app instance."""
    flask_app.config.update({
        "TESTING": True,
        # Disable CSRF protection for testing if you have it
        "WTF_CSRF_ENABLED": False,
    })
    yield flask_app


@pytest.fixture()
def client(app):
    """A fixture that provides a test client for the Flask app."""
    return app.test_client()


@pytest.fixture(scope="function")
def db_mock(mocker):
    """
    Mocks the database connection and cursor for testing.
    This fixture ensures that no actual database operations are performed.
    """
    # Create a mock cursor
    mock_cursor = MagicMock()
    
    # Set up common cursor method defaults
    mock_cursor.fetchone.return_value = None
    mock_cursor.fetchall.return_value = []
    mock_cursor.lastrowid = 1
    
    # Create a mock database connection  
    mock_db = MagicMock()
    mock_db.cursor.return_value = mock_cursor
    mock_db.commit.return_value = None
    mock_db.rollback.return_value = None
    
    # Patch the actual database connection in the app module
    mocker.patch('app.db', mock_db)
    
    return {
        'db': mock_db,
        'cursor': mock_cursor
    }


@pytest.fixture
def mock_session(mocker):
    """Mock Flask session for testing authenticated routes."""
    session_mock = {}
    mocker.patch('app.session', session_mock)
    return session_mock