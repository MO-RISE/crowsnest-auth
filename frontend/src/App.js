
import * as React from "react";
import { Admin, Resource, EditGuesser } from 'react-admin';
import jsonServerProvider from 'ra-data-json-server';
import {
  BrowserRouter,
  Routes,
  Route
} from "react-router-dom";
import { UserList } from './users';
import { LoginPage } from './login';
import authProvider from './authProvider';


const dataProvider = jsonServerProvider('http://localhost/auth/api');

const ReactAdmin = () => (
      <Admin basename="/admin" loginPage={<LoginPage admin />} dataProvider={dataProvider} authProvider={authProvider}>
          <Resource name="users" list={UserList} edit={EditGuesser}/>
      </Admin>
  );


const App = () => (
  <BrowserRouter basename="/auth">
    <Routes>
      <Route path="/admin/*" element={<ReactAdmin />} />
      <Route path="/" element={<LoginPage />} />
    </Routes>
  </BrowserRouter>
)

export default App;