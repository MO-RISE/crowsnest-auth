import * as React from "react";

import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField';
import Backdrop from '@mui/material/Backdrop';
import InputAdornment from '@mui/material/InputAdornment';
import VisibilityIcon from '@mui/icons-material/Visibility';
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import OutlinedInput from '@mui/material/OutlinedInput';
import InputLabel from '@mui/material/InputLabel';
import FormControl from '@mui/material/FormControl';

import { SnackbarProvider, useSnackbar } from 'notistack';

import { ReactComponent as CrowsnestLogo } from './crowsnest-logo.svg';

import { useLogin } from 'react-admin';

export async function login ({username, password}) {
    const request = new Request('http://' + window.location.hostname + '/auth/api/login', {
        method: 'POST',
        credentials: 'include',
        body: "username="+username+"&password="+password+"&grant_type=password",
        headers: new Headers({'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'}),
    });
    const response = await fetch(request)
    if (response.status !== 200) {
        const data = await response.json()
        throw new Error(data.detail)
    }
    return response
}


function LoginPrompt({admin}) {
    const [values, setValues] = React.useState({
        username: '',
        password: '',
        showPassword: false,
        errorMessage: '',
        disableButton: false,

    })

    const { enqueueSnackbar } = useSnackbar();
    
    const reactAdminLogin = useLogin()

    const [state, setState] = React.useState({
        redirectUrl: "http://" + window.location.hostname + "/auth",
        redirectMessage: '',
        logged: false,
        username: ''
    })
    
    const handleChange = (prop) => (event) => {
        setValues({ ...values, [prop]: event.target.value, disableButton:false, errorMessage:'' });
    };

    const handleClickShowPassword = () => {
        setValues({...values, showPassword: !values.showPassword})
    }

    const handleMouseDownPassword = (event) => {
        event.preventDefault();
    };

    const handleLogin = async () => {
        if (values.username.length < 1 || values.password.length < 1) {
            enqueueSnackbar("Username or password are empty", {variant:"error"})
            setValues({...values, disableButton: true})
        } else {
            if (admin) {
                reactAdminLogin({username: values.username, password: values.password}).catch(
                    (e)=>{ enqueueSnackbar(e.message, {variant:"error"})}
                )
            } else {
                try {
                    const response = await login({username: values.username, password: values.password})
                    response.then(window.location.replace(state.redirectUrl))
                } catch (error) {
                    enqueueSnackbar(error.message, {variant:"error"})
                };
        }
      }
    }

    const handleLogout = async() => {
        fetch('http://' +  window.location.hostname + '/auth/api/logout',{method: 'POST'}).then(response => {
            if (response.ok) {
                window.location.replace(state.redirectUrl)
            } else {
                setValues({...values, errorMessage: "Unexpected error!"})
            }
        })
    }

    // Parse url
    React.useEffect(() => {
        const queryString = window.location.search;
        const urlParams = new URLSearchParams(queryString);
        const url = urlParams.get('url')
        if (url) {
            setState(s => ({...s, redirectUrl: url}))
        }
        const message = urlParams.get('message')
        if (message) {
            setState(s => ({...s, redirectMessage: message}))
        }
    },[])

    // Determine if already logged in
    React.useEffect(() => {
        fetch('http://' +  window.location.hostname + '/auth/api/status',{credentials:'include',headers:{'Accept': 'application/json'}}).then(
            response => response.json()).then(
                data => {
                    setState(s => ({...s, username: data.username, logged: data.logged,}))
                })
    },[])   

    // Pressing "Enter" is submits the credentials.
    React.useEffect(() => {
        const listener = event => {
          if (event.code === "Enter" || event.code === "NumpadEnter") {
            event.preventDefault();
            if (!values.disableButton) {
                //handleLogin()
            }
          }
        };
        document.addEventListener("keydown", listener);
        return () => {
          document.removeEventListener("keydown", listener);
        };
    }, [values]);

    const Login = <>
        <Box>
                    <TextField
                        sx={{m: 1, width: '25ch'}}
                        label={'Username'}
                        margin={'normal'}
                        onChange={handleChange('username')}
                        required
                    />
                </Box>
                <Box>
                    <FormControl sx={{ m: 1, width: '25ch' }} variant="outlined">
                        <InputLabel htmlFor="outlined-adornment-password">Password</InputLabel>
                        <OutlinedInput
                            id="outlined-adornment-password"
                            type={values.showPassword ? 'text' : 'password'}

                            onChange={handleChange('password')}
                            endAdornment={
                                <InputAdornment position="end">
                                    <IconButton
                                    aria-label="toggle password visibility"
                                    onClick={handleClickShowPassword}
                                    onMouseDown={handleMouseDownPassword}
                                    edge="end"
                                    >
                                    {values.showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                                    </IconButton>
                                </InputAdornment>
                            }
                            label="Password"
                        />
                    </FormControl>
                </Box>
                <Box sx={{textAlign: 'center'}}>
                    <Button variant="text" disabled={values.disableButton} onClick={()=>handleLogin()}>Login</Button>
                </Box>
                
    </>

    const Logout = <>
        <Box sx={{textAlign: 'center'}}>
            <Typography variant='caption'>Logged-in as:</Typography>
        </Box>
        {state.admin && <Box>
            <Typography variant="caption">Administrator</Typography>
        </Box>}
        <Box sx={{textAlign: 'center'}}>
            <Typography variant='body2'>{state.username}</Typography>
        </Box>
        <Box sx={{textAlign: 'center'}}>
            {state.redirectMessage.length !== 0 && <Typography sx={{color: 'error.main'}}>{state.redirectMessage}</Typography> }
        </Box>
        <Box sx={{textAlign: 'center'}}>
            <Button variant="text" disabled={values.disableButton} onClick={()=>handleLogout()}>Logout</Button>
        </Box>
    </>

    return <Box sx={{
                bgcolor: 'background.paper',
                boxShadow: 1,
                borderRadius: 1,
                p: 2,
            }}>
                <Box sx={{
                    m: 1,
                    width: '25ch',
                    textAlign: 'center',
                }}>
                    <CrowsnestLogo style={{ height: 150, width: 150 }} />
                </Box>
                {admin && <Box sx={{textAlign: 'center'}}>
                    <Typography variant="h8">Administrators</Typography>
                </Box>}
                <Box sx={{textAlign: 'center'}}>
                    {state.redirectMessage.length !== 0 && <Typography sx={{color: 'error.main'}}>{state.redirectMessage}</Typography> }
                </Box>
                {state.logged ? Logout : Login}
                <Box sx={{textAlign: 'center'}}>
                    {values.errorMessage.length !== 0 && <Typography sx={{color: 'error.main'}}>{values.errorMessage}</Typography> }
                </Box>
                
            </Box>
      
    
}

export const LoginPage = ({admin}) => (
    <SnackbarProvider maxSnack={3} anchorOrigin={{
        vertical: 'bottom',
        horizontal: 'center',
      }}>
        <Backdrop open>
            <LoginPrompt admin={admin} />
        </Backdrop>
    </SnackbarProvider>
)