"""
MongoDB connection handler
"""
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import streamlit as st


class DatabaseConnection:
    """MongoDB connection manager (Singleton pattern)"""

    _instance = None
    _client = None
    _db = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._client is None:
            self. connect()

    def connect(self):
        """Establish MongoDB connection"""
        try:
            mongodb_uri = st.secrets["mongodb"]["MONGODB_URI"]
            if not mongodb_uri:
                raise ValueError(
                    "MongoDB URI not found in environment variables")

            self._client = MongoClient(mongodb_uri)

            # Test connection
            self._client.admin.command('ping')

            db_name = st.secrets['mongodb']['DATABASE_NAME']
            self._db = self._client[db_name]

            # Create indexes
            self._setup_indexes()

            print("✓ Connected to MongoDB successfully")

        except ConnectionFailure as e:
            print(f"✗ Failed to connect to MongoDB: {e}")
            raise

    def _setup_indexes(self):
        """Create database indexes for performance"""
        # User indexes
        self._db.users.create_index("username", unique=True)
        self._db.users.create_index("email", unique=True)

        # File indexes
        self._db.files.create_index("owner")
        self._db.files. create_index("file_id", unique=True)
        self._db.files.create_index([("owner", 1), ("filename", 1)])

        # Access log indexes
        self._db. access_logs.create_index([("timestamp", -1)])
        self._db. access_logs.create_index("user")

        # Security log indexes
        self._db.security_logs.create_index([("timestamp", -1)])
        self._db.security_logs.create_index("threat_level")

    @property
    def db(self):
        """Get database instance"""
        if self._db is None:
            self.connect()
        return self._db

    def get_collection(self, collection_name: str):
        """Get specific collection"""
        return self. db[collection_name]

    def close(self):
        """Close database connection"""
        if self._client:
            self._client.close()
            print("✓ Database connection closed")


# Singleton instance
db_connection = DatabaseConnection()
