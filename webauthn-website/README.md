# Simple WebAuthn demo
Implementation of WebAuthn API written in React and Express.
Demo that shows the future of passwordless authentication.
Users register with a username and one of the supported authenticators.
Login process requires matching username and authenticator pair.

## Demo link:
https://u2f-858.herokuapp.com/

## Installation
### Requirements
  - Node.js
  - MongoDB (local or remote cluster)
### Setup
  - Run `npm install`
  - Configure environment variables in `.env` file, use `.env.example` as guide. MongoDB connection is required for the app to run.
  If the app is run locally then it's not necessary to provide RP Id(Relaying Party ID) as it defaults to localhost, else you must provide RP Id to match your origin e.g.`RP_ID=u2f-858.herokuapp.com`  
## Launch
### Development
  - Client: `npm run dev:client`
  - Server `npm run dev:server`
### Production 
  - First run `npm run build`
  - Then run `npm start` to start the server.
### Heroku push
  - First check if you're in the webauthn-website directory, otherwise `cd webauthn-website`
  - Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)
  - `heroku login`
  - make sure you have access to the u2f-858 project
  - Then add your changes by `git add .` and `git commit -m'hi'`
  - To deploy to heroku and see changes on the website, run `git push heroku main`
  - to change config vars, do it within the [online dashboard](https://dashboard.heroku.com/apps/u2f-858/settings).

## Notes
### Supported Attestation formats
  - Packed
  - Fido-U2F
