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


