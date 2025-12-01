"""
Quick test to verify MongoDB connection
"""
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get connection string
mongodb_uri = os.getenv('MONGODB_URI')

print("Testing MongoDB Atlas Connection...")
print("=" * 60)

if not mongodb_uri:
    print("❌ ERROR: MONGODB_URI not found in . env file")
    print("Please create a .env file with your MongoDB connection string")
    exit(1)

# Mask password in output for security
masked_uri = mongodb_uri
if '@' in masked_uri:
    parts = masked_uri.split('@')
    if ':' in parts[0]:
        user_pass = parts[0].split('://')[-1]
        username = user_pass.split(':')[0]
        masked_uri = masked_uri.replace(user_pass, f"{username}:****")

print(f"Connection String: {masked_uri}")
print("=" * 60)

try:
    # Create client
    print("\n1. Creating MongoDB client...")
    client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)

    # Test connection
    print("2. Testing connection (ping)...")
    client.admin. command('ping')

    # Get database
    db_name = os.getenv('DATABASE_NAME', 'secure_file_mgmt')
    db = client[db_name]

    # List collections
    print(f"3. Accessing database: {db_name}")
    collections = db.list_collection_names()

    # Insert test document
    print("4. Inserting test document...")
    test_collection = db['test_connection']
    result = test_collection.insert_one(
        {"test": "success", "timestamp": "2025-12-01"})

    # Read test document
    print("5. Reading test document...")
    doc = test_collection.find_one({"_id": result.inserted_id})

    # Clean up
    print("6.  Cleaning up...")
    test_collection.delete_one({"_id": result.inserted_id})

    print("\n" + "=" * 60)
    print("✅ SUCCESS! MongoDB Atlas connection is working perfectly!")
    print("=" * 60)
    print(f"\nDatabase: {db_name}")
    print(
        f"Existing Collections: {collections if collections else 'None (new database)'}")
    print("\nYou're ready to proceed with development! 🚀")

except Exception as e:
    print("\n" + "=" * 60)
    print("❌ CONNECTION FAILED")
    print("=" * 60)
    print(f"\nError: {e}")
    print("\nCommon solutions:")
    print("1. Check if <password> is replaced with your actual password")
    print("2. Check if your IP is whitelisted (0.0.0.0/0 for all IPs)")
    print("3.  Check if database user exists and has correct permissions")
    print("4.  URL encode special characters in password")
    print("5. Check your internet connection")

finally:
    if 'client' in locals():
        client.close()
