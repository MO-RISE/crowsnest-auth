# crowsnest-auth
Authentication and Authorization microservice for crowsnest

Designed to work with:
* [Traefik forward auth](https://doc.traefik.io/traefik/v2.0/middlewares/forwardauth/)
* [EMQX http auth](https://docs.emqx.io/en/broker/v4.3/advanced/auth-http.html)
* [EMQX http acl](https://docs.emqx.io/en/broker/v4.3/advanced/acl-http.html)



## Example setup

See `docker-compose.dev.yml`

## Development
Requires:
* python >= 3.8
* docker and docker-compose
* vscode (optional, but very handy) (with python and docker extensions)

Install the python requirements in a virtual environment:
```cmd
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements_dev.txt
```

### Developing/debugging
Get a development/debug session running:
1. Open vscode with the repo root as the workspace directory
2. Make sure vscode detects your virtual environment
3. Start the docker-compose stack defined in `docker-compose.dev.yml` 
4. Start `main.py` through the vs code debugger (F5 button)

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

