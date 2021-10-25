"""OAuth2 implementation for using either a Bearer token or a cookie"""
from typing import Dict, Optional

from fastapi.exceptions import HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.security import OAuth2
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED


class OAuth2PasswordBearerOrCookie(OAuth2):  # pylint: disable=too-few-public-methods
    """An Oauth2 implemtnation for FastAPI allowing to use either a
    bearer token or a cookie for carrying the token

    All config same as for Oauth2 (parent class) except for:

    Args:
        cookie_name (str): The name of the cookie to access

    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        tokenUrl: str,
        cookie_name: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )
        self.cookie_name = cookie_name

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)

        if not token or token.lower() == "undefined" or scheme.lower() != "bearer":
            token: str = request.cookies.get(self.cookie_name)

        if not token:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )

            return None
        return token
