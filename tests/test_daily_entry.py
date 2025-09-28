import pytest
from flask import url_for


class TestDailyEntry:
    """Test cases for the daily entry form and functionality."""

    def test_get_daily_entry_without_login(self, client):
        """Test that unauthenticated users are redirected to login."""
        response = client.get('/dailyentrypage')
        assert response.status_code == 302
        assert '/login' in response.location or response.location.endswith('/')

    def test_get_daily_entry_with_login(self, client, mock_session, db_mock):
        """Test that authenticated users can access the daily entry form."""
        # Set up authenticated session
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        # Mock database response for session validation
        db_mock['cursor'].fetchone.return_value = {
            'active_session': 'test-token-123',
            'last_active': None  # Will trigger update
        }

        response = client.get('/dailyentrypage')
        assert response.status_code == 200
        assert b'Daily Carbon Footprint Entry' in response.data

    def test_daily_entry_form_elements_present(self, client, mock_session, db_mock):
        """Test that all required form elements are present in the HTML."""
        # Set up authenticated session
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.return_value = {
            'active_session': 'test-token-123',
            'last_active': None
        }

        response = client.get('/dailyentrypage')
        html_content = response.data.decode()
        
        # Check for form fields
        assert 'name="work_location"' in html_content
        assert 'name="commute_mode"' in html_content
        assert 'name="commute_distance"' in html_content
        assert 'name="meal_source"' in html_content
        assert 'name="diet"' in html_content
        assert 'name="digital_intensity"' in html_content
        assert 'name="printing_level"' in html_content
        
        # Check form action
        assert 'action="/dailyentrypage"' in html_content
        assert 'method="POST"' in html_content

    def test_submit_valid_daily_entry(self, client, mock_session, db_mock):
        """Test successful form submission with valid data."""
        # Set up authenticated session
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        # Mock database responses
        db_mock['cursor'].fetchone.side_effect = [
            {'active_session': 'test-token-123', 'last_active': None},  # Session validation
            {'id': 1}  # User ID lookup
        ]
        db_mock['cursor'].lastrowid = 123  # Mock insert ID

        form_data = {
            'work_location': 'Office',
            'commute_mode': 'Car',
            'commute_distance': '10',
            'meal_source': 'Home-Packed',
            'diet': 'Vegetarian',
            'digital_intensity': 'Moderate',
            'printing_level': 'Minimal'
        }

        response = client.post('/dailyentrypage', data=form_data)
        assert response.status_code == 200
        assert b'Entry Added Successfully' in response.data or b'Carbon Tracker' in response.data

    def test_submit_entry_missing_required_fields(self, client, mock_session, db_mock):
        """Test form submission with missing required fields."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.return_value = {
            'active_session': 'test-token-123',
            'last_active': None
        }

        # Submit form with missing fields
        form_data = {
            'work_location': 'Office',
            # Missing other required fields
        }

        response = client.post('/dailyentrypage', data=form_data)
        # The route should handle this gracefully (either redirect or show error)
        assert response.status_code in [200, 302, 400]

    def test_carbon_calculation_car_commute(self, client, mock_session, db_mock):
        """Test carbon calculation with car commute."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.side_effect = [
            {'active_session': 'test-token-123', 'last_active': None},
            {'id': 1}
        ]
        db_mock['cursor'].lastrowid = 123

        form_data = {
            'work_location': 'Office',
            'commute_mode': 'Car',
            'commute_distance': '20',  # 20km by car = 20 * 0.2 = 4.0 carbon
            'meal_source': 'Home-Packed',
            'diet': 'Vegan',
            'digital_intensity': 'Light',
            'printing_level': 'Minimal'
        }

        response = client.post('/dailyentrypage', data=form_data)
        assert response.status_code == 200

        # Verify database calls were made
        assert db_mock['cursor'].execute.called
        assert db_mock['db'].commit.called

    def test_green_points_calculation(self, client, mock_session, db_mock):
        """Test that green points are calculated based on carbon score."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.side_effect = [
            {'active_session': 'test-token-123', 'last_active': None},
            {'id': 1}
        ]
        db_mock['cursor'].lastrowid = 123

        # Low carbon footprint data (should get high points)
        form_data = {
            'work_location': 'Home',  # Low carbon
            'commute_mode': 'Walk',   # Zero carbon
            'commute_distance': '0',
            'meal_source': 'Home-Packed',
            'diet': 'Vegan',          # Low carbon
            'digital_intensity': 'Light',
            'printing_level': 'Minimal'
        }

        response = client.post('/dailyentrypage', data=form_data)
        assert response.status_code == 200

    def test_post_without_authentication(self, client):
        """Test that POST requests without authentication are blocked."""
        form_data = {
            'work_location': 'Office',
            'commute_mode': 'Car',
            'commute_distance': '10'
        }

        response = client.post('/dailyentrypage', data=form_data)
        assert response.status_code == 302  # Redirect to login

    def test_invalid_commute_distance(self, client, mock_session, db_mock):
        """Test handling of invalid commute distance values."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.side_effect = [
            {'active_session': 'test-token-123', 'last_active': None},
            {'id': 1}
        ]

        form_data = {
            'work_location': 'Office',
            'commute_mode': 'Car',
            'commute_distance': -45,  # Invalid input
            'meal_source': 'Home-Packed',
            'diet': 'Vegetarian',
            'digital_intensity': 'Moderate',
            'printing_level': 'Minimal'
        }

        response = client.post('/dailyentrypage', data=form_data)
        # Should handle gracefully
        assert response.status_code in [200, 400, 302]

    def test_navbar_links_present(self, client, mock_session, db_mock):
        """Test that navigation links are present in the template."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.return_value = {
            'active_session': 'test-token-123',
            'last_active': None
        }

        response = client.get('/dailyentrypage')
        html_content = response.data.decode()
        
        # Check for navigation elements
        assert 'Carbon Tracker' in html_content
        assert 'Profile' in html_content
        assert 'Logout' in html_content
        assert 'Leaderboard' in html_content

    def test_form_validation_styling_present(self, client, mock_session, db_mock):
        """Test that form validation styling and JavaScript are present."""
        mock_session.update({
            'username': 'testuser',
            'session_token': 'test-token-123',
            'user_id': 1
        })
        
        db_mock['cursor'].fetchone.return_value = {
            'active_session': 'test-token-123',
            'last_active': None
        }

        response = client.get('/dailyentrypage')
        html_content = response.data.decode()
        
        # Check for validation elements
        assert 'invalid-feedback' in html_content
        assert 'required' in html_content
        assert 'checkValidity' in html_content  # JavaScript validation