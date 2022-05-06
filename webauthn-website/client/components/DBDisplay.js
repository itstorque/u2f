import React, { useState, useEffect } from 'react';

// import './Main.css';
import { Header, Label, Menu, Table } from 'semantic-ui-react';
import { getAllUsers } from './webauthn';


function DBDisplay() {

	// display all users using getAllUsers()
	const [users, setUsers] = useState([]);
	useEffect(() => {
		getAllUsers()
			.then(users => {
				setUsers(users);
			})
			.catch(err => {
				console.log(err);
			});
	}, []);

	return (
		<div >
			<Header as='h1'>Database Display</Header>
			<Table celled >
				<Table.Header>
					<Table.Row>
						<Table.HeaderCell>Index</Table.HeaderCell>
						<Table.HeaderCell>ID</Table.HeaderCell>
						<Table.HeaderCell>Name</Table.HeaderCell>
						<Table.HeaderCell>Email</Table.HeaderCell>
						<Table.HeaderCell>Counter</Table.HeaderCell>
						<Table.HeaderCell>Public Key</Table.HeaderCell>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{/* display users row by row*/}
					{users.map((user, index) => (
						<Table.Row key={user.id}>
							<Table.Cell>{index + 1}</Table.Cell>
							<Table.Cell>{user.id}</Table.Cell>
							<Table.Cell>{user.name}</Table.Cell>
							<Table.Cell>{user.email}</Table.Cell>
							<Table.Cell>{user.counter? user.counter: -1}</Table.Cell>
							<Table.Cell>{user.authenticators[0]? user.authenticators[0].publicKey: 'none'}</Table.Cell>
						</Table.Row>
					))}
				</Table.Body>

			</Table>

		</div>
	);
}

export default DBDisplay;
