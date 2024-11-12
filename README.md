# Prophet Security Backend Service

## Setup Instructions

### On Local Machine

#### Prerequisites:
- **Python 3.8+**
- **PostgreSQL database**

#### Steps:

1. **Clone the repository**:
    ```
    git clone https://github.com/TMhalsekar/prophet-security-takehome
    ```

2. **Install dependencies**:
    ```
    pip install -r requirements.txt
    ```

3. **Configure PostgreSQL** in `database.py` with your credentials and database name:
    ```
    DATABASE_URL = "postgresql://{username:password}@localhost:5432/{database_name}"
    ```

4. **Start the FastAPI server**:
    ```
    uvicorn app:app --reload
    ```

### Using Docker

1. **Clone the repository**:
    ```
    git clone https://github.com/TMhalsekar/prophet-security-takehome
    ```

2. **Run with Docker Compose**:
    ```
    docker-compose up --build
    ```

3. **Access the application** at [http://localhost:8000](http://localhost:8000) and view the documentation and test the application at [http://localhost:8000/docs](http://localhost:8000/docs).
