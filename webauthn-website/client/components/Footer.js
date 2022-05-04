import React, { Component } from 'react'
import { Input, Menu } from 'semantic-ui-react'
import { NavLink, withRouter } from 'react-router-dom'

export default class Footer extends Component {
    render() {

        return (
            <Menu secondary>
                <Menu.Item
                    as={NavLink} to="/"
                    name='Demo'
                    onClick={this.handleItemClick}
                />
                <Menu.Item
                    as={NavLink} to="/db-display"
                    name='DB'
                    onClick={this.handleItemClick}
                />
            </Menu>
        )
    }
}