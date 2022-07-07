
import {login} from './login'

const authProvider = {
    login: login,
    logout: () => {
        const request = new Request('http://' + window.location.hostname + '/auth/api/logout', {
            method: 'POST',
            credentials: 'include',
        });
        return fetch(request)
            .then(response => {
                if (response.status < 200 || response.status >= 300) {
                    throw new Error(response.statusText);
                }
            })
    },
    checkAuth: () => {
        const request = new Request('http://' + window.location.hostname + '/auth/api/me', {
            method: 'GET',
            credentials: 'include',
        })
        return fetch(request).then(response => {
            if (response.status !== 200) {
                response.json().then(data => {
                    throw new Error(data.detail)
                })
            }
            return response.json()
        }).then(data => {
            if (!data.admin) {
                throw new Error('Not an administrator')
            }
            return data
        })
    },
    checkError:  (error) => {
        const status = error.status;
        if (status === 401 || status === 403) {
            return Promise.reject({redirectTo:'/admin/login',logoutUser: false});
        }
        // other error code (404, 500, etc): no need to log out
        return Promise.resolve();
    },
    getIdentity: () => {
        const request = new Request('http://' + window.location.hostname + '/auth/api/me', {
            method: 'GET',
            credentials: 'include',
        })
        const data = fetch(request).then(response=>response.json()).then((data) => { 
            return {
            id: data.username,
            fullName: data.firstname + ' ' + data.lastname,
        }})
        
        
        return Promise.resolve(data)
    },
    getPermissions: () => Promise.resolve(''),
};

export default authProvider