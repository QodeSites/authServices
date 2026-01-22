
from models.models import UserApplication, AuthMethod, UserCredential, AuthProviderEnum, User
from db.session import get_db_session
import pandas as pd 

def main():
    df = pd.read_csv("pms_clients_master.csv")
    db = get_db_session()


    # Iterate through each row and create User and UserApplication entries for application_id 2 and 3
    for i, row in df.iterrows():
        # Compose the required fields
        # Skip if password is nan, None, or equals "Qode@123"
        if pd.isna(row['password']) or row['password'] is None or row['password'] == "Qode@123":
            continue

        print(row['password'],"===+")
        email = row["email"].strip()
        username = row["clientname"].strip()
        print(row['firstname'],row['lastname'],row['clientname'],"==========")
        try:
            full_name = f"{row['clientname'].strip()}".strip()
        except:
            full_name = f"{row['firstname'].strip()} {row['lastname'].strip()}".strip()
        is_active = True
        is_verified = False

        # bcrypt hash is already present in dataframe column "password"
        hashed_password = row["password"].strip()
        password_algo = "bcrypt"

        # Check if user already exists
        user = db.query(User).filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                username=username,
                full_name=full_name,
                is_active=is_active,
                is_verified=is_verified,
            )
            db.add(user)
            db.flush()  # To get user.id

        # Create UserApplication for application_id 2 and 3 and add local AuthMethod + UserCredential
        for application_id in [2, 3]:
            ua = (
                db.query(UserApplication)
                .filter_by(user_id=user.id, application_id=application_id)
                .first()
            )
            if not ua:
                user_application = UserApplication(
                    user_id=user.id,
                    application_id=application_id,
                )
                db.add(user_application)
                db.flush()
            else:
                user_application = ua

            # Add AuthMethod (local) if doesn't exist for this user_application
            auth_method = (
                db.query(AuthMethod)
                .filter_by(user_application_id=user_application.id, provider=AuthProviderEnum.LOCAL)
                .first()
            )
            if not auth_method:
                auth_method = AuthMethod(
                    user_application_id=user_application.id,
                    provider=AuthProviderEnum.LOCAL,
                    is_primary=True
                )
                db.add(auth_method)
                db.flush()

                # Add UserCredential linked to this AuthMethod (column is named "password_hash")
                user_credential = UserCredential(
                    auth_method_id=auth_method.id,
                    password_hash=hashed_password,
                    password_algo=password_algo,
                    failed_attempts=0,
                    is_locked=False
                )
                db.add(user_credential)

    db.commit()



if __name__ == "__main__":
    main()