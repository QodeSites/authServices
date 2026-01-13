import secrets
import hashlib
from datetime import datetime, timezone
from models.models import Application, Service, ApplicationService, ServiceAccount, ServiceAccountPermission
from db.session import get_db_session

def generate_client_id(name: str) -> str:
    """Generate a unique client ID"""
    timestamp = datetime.now(timezone.utc).timestamp()
    return hashlib.sha256(f"{name}_{timestamp}".encode()).hexdigest()[:32]


def generate_client_secret() -> str:
    """Generate a secure client secret"""
    return secrets.token_urlsafe(64)


def generate_service_key(name: str) -> str:
    """Generate a service key"""
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def populate_applications_and_services(db):
    """Populate applications, services, and their relationships"""
    
    applications_data = [
        {"name": "QodePulseApp", "type": "application"},
        {"name": "QodePulseService", "type": "backend"},
        {"name": "MyQodeApp", "type": "application"},
        {"name": "MyQode", "type": "application"},
        {"name": "MyQodeService", "type": "backend"},
        {"name": "Qode360", "type": "application"},
        {"name": "Qode360Service", "type": "backend"},
    ]
    
    print("=" * 60)
    print("STARTING DATABASE POPULATION")
    print("=" * 60)
    
    # Separate applications and services
    apps_to_create = [app for app in applications_data if app["type"] == "application"]
    services_to_create = [app for app in applications_data if app["type"] == "backend"]
    
    # Create Applications
    print("\n📱 CREATING APPLICATIONS...")
    print("-" * 60)
    created_applications = []
    for app_data in apps_to_create:
        client_id = generate_client_id(app_data["name"])
        client_secret = generate_client_secret()
        
        application = Application(
            name=app_data["name"],
            client_id=client_id,
            client_secret=client_secret,
            is_active=True
        )
        db.add(application)
        db.flush()  # Get the ID without committing
        created_applications.append(application)
        
        print(f"✅ Application: {app_data['name']}")
        print(f"   ID: {application.id}")
        print(f"   Client ID: {client_id}")
        print(f"   Client Secret: {client_secret}")
        print()
    
    # Create Services
    print("\n🔧 CREATING SERVICES...")
    print("-" * 60)
    created_services = []
    for service_data in services_to_create:
        service_key = generate_service_key(service_data["name"])
        
        service = Service(
            name=service_data["name"],
            service_key=service_key,
            is_active=True
        )
        db.add(service)
        db.flush()
        created_services.append(service)
        
        print(f"✅ Service: {service_data['name']}")
        print(f"   ID: {service.id}")
        print(f"   Service Key: {service_key}")
        print()
    
    # Link all applications to all services (full mesh)
    print("\n🔗 LINKING APPLICATIONS TO SERVICES (Full Mesh)...")
    print("-" * 60)
    for application in created_applications:
        for service in created_services:
            app_service = ApplicationService(
                application_id=application.id,
                service_id=service.id
            )
            db.add(app_service)
            print(f"✅ Linked: {application.name} → {service.name}")
    
    print()
    
    # Create Service Accounts (one for each service)
    print("\n🤖 CREATING SERVICE ACCOUNTS...")
    print("-" * 60)
    created_service_accounts = []
    for service in created_services:
        client_id = generate_client_id(f"SA_{service.name}")
        client_secret = generate_client_secret()
        
        service_account = ServiceAccount(
            name=f"{service.name}_Account",
            client_id=client_id,
            client_secret=client_secret,
            is_active=True
        )
        db.add(service_account)
        db.flush()
        created_service_accounts.append(service_account)
        
        print(f"✅ Service Account: {service_account.name}")
        print(f"   ID: {service_account.id}")
        print(f"   Client ID: {client_id}")
        print(f"   Client Secret: {client_secret}")
        print()
    
    # Link service accounts to all services (full mesh)
    print("\n🔗 LINKING SERVICE ACCOUNTS TO SERVICES (Full Mesh)...")
    print("-" * 60)
    for service_account in created_service_accounts:
        for service in created_services:
            sa_permission = ServiceAccountPermission(
                service_account_id=service_account.id,
                service_id=service.id
            )
            db.add(sa_permission)
            print(f"✅ Linked: {service_account.name} → {service.name}")
    
    print()
    
    # Commit all changes
    db.commit()
    
    print("\n" + "=" * 60)
    print("✅ DATABASE POPULATION COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    
    # Summary
    print("\n📊 SUMMARY:")
    print(f"   Applications Created: {len(created_applications)}")
    print(f"   Services Created: {len(created_services)}")
    print(f"   Service Accounts Created: {len(created_service_accounts)}")
    print(f"   App-Service Links: {len(created_applications) * len(created_services)}")
    print(f"   Service Account Permissions: {len(created_service_accounts) * len(created_services)}")
    print()
    
    return {
        "applications": created_applications,
        "services": created_services,
        "service_accounts": created_service_accounts
    }


def print_credentials_summary(db):
    """Print a clean summary of all credentials for reference"""
    print("\n" + "=" * 60)
    print("📋 CREDENTIALS REFERENCE")
    print("=" * 60)
    
    print("\n🔑 APPLICATIONS:")
    print("-" * 60)
    applications = db.query(Application).all()
    for app in applications:
        print(f"\n{app.name}:")
        print(f"  Client ID:     {app.client_id}")
        print(f"  Client Secret: {app.client_secret}")
    
    print("\n\n🔑 SERVICES:")
    print("-" * 60)
    services = db.query(Service).all()
    for service in services:
        print(f"\n{service.name}:")
        print(f"  Service Key: {service.service_key}")
    
    print("\n\n🔑 SERVICE ACCOUNTS:")
    print("-" * 60)
    service_accounts = db.query(ServiceAccount).all()
    for sa in service_accounts:
        print(f"\n{sa.name}:")
        print(f"  Client ID:     {sa.client_id}")
        print(f"  Client Secret: {sa.client_secret}")
        
        # Show allowed services
        permissions = db.query(ServiceAccountPermission).filter_by(
            service_account_id=sa.id
        ).all()
        service_names = [
            db.query(Service).get(p.service_id).name 
            for p in permissions
        ]
        print(f"  Allowed Services: {', '.join(service_names)}")
    
    print("\n" + "=" * 60)


def main():
    """Main function to run the population script"""
    
    # Create database session
    db = get_db_session()
    
    try:
        # Check if data already exists
        existing_apps = db.query(Application).count()
        existing_services = db.query(Service).count()
        
        if existing_apps > 0 or existing_services > 0:
            print("⚠️  WARNING: Database already contains data!")
            print(f"   Applications: {existing_apps}")
            print(f"   Services: {existing_services}")
            response = input("\n   Do you want to continue? This will add more data. (yes/no): ")
            if response.lower() != 'yes':
                print("❌ Operation cancelled.")
                return
        
        # Populate the database
        result = populate_applications_and_services(db)
        
        # Print credentials summary
        print_credentials_summary(db)
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()