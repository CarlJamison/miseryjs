const fs = require('fs');
const path = require('path');
const storage = "file_storage"
const { v4: uuidv4 } = require('uuid');

module.exports = {
    handlers: [
        {   
            returnType: 1,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;

                var buffer = Buffer.from(message.output, 'base64');
                
                if(!fs.existsSync(storage)){
                    fs.mkdirSync(storage);
                }
                
                if(!fs.existsSync(`${storage}/${cust.id}`)){
                    fs.mkdirSync(`${storage}/${cust.id}`);
                }

                fs.writeFile(`${storage}/${cust.id}/${uuidv4()}`, buffer, (err) => {
                    scope.controllers.emit('echo', err ? err.toString() : 'File added to server storage');
                });
                
                return true;
            }
        }
    ],
    listeners:[
        {
            name: 'server-upload',
            handle: (scope, msg) => {
                if(!fs.existsSync(storage)){
                    fs.mkdirSync(storage);
                }

                var buffer = Buffer.from(msg.args[1], 'base64');

                fs.writeFile(`${file_storage}/${msg.args[0]}`, buffer, (err) => {
                    scope.socket.emit('echo', err ? err.toString() : 'File uploaded');
                });
            }
        },
        {
            name: 'current-server-storage',
            handle: (scope, msg) => {
                if(!fs.existsSync(storage)){
                    fs.mkdirSync(storage);
                }

                var result = dirTree(storage)
                scope.socket.emit('echo', dirTreeString(storage));
            }
        }
    ]

}

function dirTree(filename) {
    var stats = fs.lstatSync(filename),
        info = {
            path: filename,
            name: path.basename(filename)
        };

    if (stats.isDirectory()) {
        info.type = "folder";
        info.children = fs.readdirSync(filename).map(function(child) {
            return dirTree(filename + '/' + child);
        });
    } else {
        info.type = "file";
    }

    return info;
}

function dirTreeString(filename, out = "", indent = "") {
    var stats = fs.lstatSync(filename);

    var out = indent + path.basename(filename) + "\n";

    if (stats.isDirectory()) {
        fs.readdirSync(filename).map(function(child) {
            out += dirTreeString(filename + '/' + child, out, indent + "\t");
        });
    }

    return out;
}