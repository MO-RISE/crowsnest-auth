import * as React from "react";
import { List, Datagrid, TextField, EmailField } from 'react-admin';


export const UserList = () => (
    <List>
        <Datagrid rowClick="edit">
  
            <TextField source="username" />
            <EmailField source="email" />
        </Datagrid>
    </List>
  );