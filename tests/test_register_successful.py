from urllib import response


def test_signup_page_load_successfull(client):
    """Test that the signup page loads successfully"""
    response = client.get("/signup")
    assert response.status_code == 200

    assert b"Create Your Account" in response.data


def test_signup_details(client):
    response = client.post(
        "/register",
        data={
            
            "phone": "8989404118",
            
        },
        follow_redirects=True,
    )
    assert b"Invalid phone number" in response.data
    # assert b"Create Your Account" in response.data
    # assert b"Username already exist" in response.data
    