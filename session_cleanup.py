import threading
from datetime import datetime, timedelta
from app import db

def cleanup_expired_sessions():
    """Clean up expired sessions periodically"""
    while True:
        try:
            conn = db
            with conn.cursor() as cursor:
                # Clean up sessions older than the inactivity limit
                cursor.execute(
                    """
                    UPDATE SignupDetails 
                    SET active_session = NULL, last_active = NULL 
                    WHERE last_active < %s
                    """,
                    (datetime.now() - timedelta(seconds=300),)  # 5 minutes
                )
                conn.commit()
        except Exception as e:
            print(f"Session cleanup error: {e}")
        finally:
            # Run every 5 minutes
            time.sleep(300)

# Start the cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
cleanup_thread.start()