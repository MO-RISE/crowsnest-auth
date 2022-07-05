# crowsnest-auth

Authentication and Authorization microservice for crowsnest

Designed to work with:

- [Traefik forward auth](https://doc.traefik.io/traefik/v2.0/middlewares/forwardauth/)
- [EMQX http auth](https://docs.emqx.io/en/broker/v4.3/advanced/auth-http.html)
- [EMQX http acl](https://docs.emqx.io/en/broker/v4.3/advanced/acl-http.html)

## Example setup

See `docker-compose.dev.yml`

## Development

Requires:

- python >= 3.8
- docker and docker-compose
- vscode
- Nodejs >= 14.0

### Setup

1. Install the python requirements in a virtual environment:

```cmd

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements_dev.txt

# with Conda
conda create -n cn-auth python=3.8
conda activate cn-auth
pip install -r requirements.txt -r requirements_dev.txt
```

2. Install the frontend dependencies:

```cmd
npm install frontend
```

3. In different terminal windows:

   a. Start Traefik in its development configuration:

   ```
   docker-compose -f docker-compose.dev.yml up
   ```

   b. Start the python API by pressing `F5` in vscode, or:

   ```cmd
   export $(xargs < .env)
   uvicorn app.main:app --reload --port 8000
   ```

   c. Start the React development server:

   ```cmd
   cd frontend
   npm start
   ```

The API's documentation is available at `http://localhost/auth/api/docs`

### Run linters

```cmd
black app tests
pylint app
```

### Run testsuite

```cmd
pytest tests/
```

**Note**: Running the testsuite will fail if you have the development docker-compose stack still running.

## Production

The following environmental variables are necessary:

- `ACCESS_COOKIE_DOMAIN` (e.g. 'www.foo.com')
- `USER_DATABASE_URL`
- `JWT_TOKEN_SECRET`

Optional environmental variables:

- `ACCESS_COOKIE_SECURE`
- `ACCESS_COOKIE_HTTPONLY`
- `ACCESS_COOKIE_SECURE`
- `ACCESS_COOKIE_HTTPONLY`
- `ACCESS_COOKIE_SAMESITE`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `ADMIN_USER_USERNAME`
- `ADMIN_USER_PASSWORD`
- `BASE_URL`
