(function() {
  'use strict';

  var port;

  let textEncoder = new TextEncoder();

  var send = (str) => {
    if (port !== undefined) {
      port.send(textEncoder.encode(str)).catch(error => {
        console.log('Send error: ' + error);
      });
    }
  }


  document.addEventListener('DOMContentLoaded', event => {
    let connectButton = document.querySelector('#connect');

    document.getElementById("sendfield").addEventListener("keydown", function (e) {
        if (e.code === "Enter") {  //checks whether the pressed key is "Enter"
            console.log("sending: " + e.target.value )
            send(e.target.value + "\0");
        }
    });

    function connect() {
      console.log('Connecting to ' + port.device_.productName + '...');
      port.connect().then(() => {
        console.log(port);
        console.log('Connected.');
        connectButton.textContent = 'Disconnect';
        port.onReceive = data => {
          let textDecoder = new TextDecoder();
          console.log(textDecoder.decode(data));
        }
        port.onReceiveError = error => {
          console.log('Receive error: ' + error);
        };
      }, error => {
        console.log('Connection error: ' + error)
        // console.log('Connection error: ' + error);
      });
    };

    connectButton.addEventListener('click', function() {
      if (port) {
        port.disconnect();
        connectButton.textContent = 'Connect';
        port = null;
      } else {
        serial.requestPort().then(selectedPort => {
          port = selectedPort;
          connect();
        }).catch(error => {
          console.log('Connection error: ' + error);
        });
      }
    });

    serial.getPorts().then(ports => {
      if (ports.length == 0) {
        console.log('No devices found.');
      } else {
        port = ports[0];
        connect();
      }
    });
  });
})();
