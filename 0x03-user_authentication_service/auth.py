#!/usr/bin/env python3
"""
This module contains the Auth class and related functions
for interacting with the authentication database.
"""

import bcrypt
from uuid import uuid4
from typing import Union
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.

    Args:
        password: The password to be hashed.

    Returns:
        The hashed password as bytes.

    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a UUID.

    Returns:
        A string representation of the generated UUID.

    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.

    Attributes:
        _db: An instance of the DB class for database operations.

    """

    def __init__(self):
        """Initializes a new Auth instance."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Adds a new user to the database.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            The User object representing the newly registered user.

        Raises:
            ValueError: If the user with the given email already exists.

        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if a user's login details are valid.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            True if the login details are valid, False otherwise.

        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                    password.encode("utf-8"),
                    user.hashed_password,
                )
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Creates a new session for a user.

        Args:
            email: The email of the user.

        Returns:
            The session ID as a string.

        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves a user based on a given session ID.

        Args:
            session_id: The session ID of the user.

        Returns:
            The User object representing the user if found, None otherwise.

        """
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session associated with a given user.

        Args:
            user_id: The ID of the user.

        """
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.

        Args:
            email: The email of the user.

        Returns:
            The password reset token as a string.

        Raises:
            ValueError: If the user with the given email does not exist.

        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password given the user's reset token.

        Args:
            reset_token: The reset token of the user.
            password: The new password for the user.

        Raises:
            ValueError: If the user with the given reset token does not exist.

        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
