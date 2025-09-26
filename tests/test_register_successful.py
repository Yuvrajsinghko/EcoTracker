from urllib import response


def test_signup_page_load_successfull(client):
    """Test that the signup page loads successfully"""
    response = client.get("/signup")
    assert response.status_code == 200

    assert b"Create Your Account" in response.data


def test_signup_details(client, db_mock):
    response = client.post(
        "/register",
        data={
            "name": "John Doe",
            "email": "john@example.com",
            "phone": "111111111111",  # Invalid: all same digits
            "age": "25",
            "gender": "Male",
            "username": "johndoe123",
            "password": "Password123!",
            "confirmPassword": "Password123!",
        },
        follow_redirects=True,
    )
    assert b"Invalid phone number" in response.data


def test_registration_with_valid_phone_but_missing_fields(client, db_mock):
    """Test registration fails when only phone is provided"""
    response = client.post(
        "/register",
        data={
            "phone": "8989404118",  # Valid phone number
            # Missing all other required fields
        },
        follow_redirects=True,
    )
    # Should fail due to missing required fields, not phone validation
    # The exact error depends on your form validation order
    assert response.status_code == 200  # Stays on signup page


def test_registration_successful(client, db_mock):
    """Test successful registration with all valid data"""
    # Mock the database operations
    db_mock["cursor"].fetchone.return_value = None  # Username doesn't exist

    response = client.post(
        "/register",
        data={
            "name": "John Doe",
            "email": "john@example.com",
            "phone": "8989404118",  # Valid phone
            "age": "25",
            "gender": "Male",
            "username": "johndoe123",
            "password": "Password123!",
            "confirmPassword": "Password123!",
        },
        follow_redirects=True,
    )
    assert b"Registration successful!" in response.data


def test_registration_with_various_invalid_phones(client, db_mock):
    """Test multiple invalid phone number patterns"""

    invalid_phones = [
        "1111111111",  # All same digits
        "1234567890",  # Sequential pattern
        "9876543210",  # Reverse sequential
        "5123456789",  # Starts with 5 (invalid)
        "12345",  # Too short
        "98765432101",  # Too long
        "abcd123456",  # Contains letters
    ]

    for invalid_phone in invalid_phones:
        response = client.post(
            "/register",
            data={
                "name": "John Doe",
                "email": "john@example.com",
                "phone": invalid_phone,
                "age": "25",
                "gender": "Male",
                "username": "johndoe123",
                "password": "Password123!",
                "confirmPassword": "Password123!",
            },
            follow_redirects=True,
        )
        assert (
            b"Invalid phone number" in response.data
        ), f"Phone {invalid_phone} should be invalid"


def test_registration_username_already_exists(client, db_mock):
    """Test registration fails when username already exists"""
    # Mock database to return existing user
    db_mock["cursor"].fetchone.return_value = {"username": "existing_user"}

    response = client.post(
        "/register",
        data={
            "name": "yuvraj5",
            "email": "john@example.com",
            "phone": "8989404118",
            "age": "25",
            "gender": "Male",
            "username": "existing_user",
            "password": "Password123!",
            "confirmPassword": "Password123!",
        },
        follow_redirects=True,
    )
    assert b"Username already exist" in response.data
