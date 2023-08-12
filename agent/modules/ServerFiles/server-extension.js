const fs = require('fs');
const path = require('path');
const storage = "file_storage"
const { v4: uuidv4 } = require('uuid');

if(!fs.existsSync(storage)){
    fs.mkdirSync(storage);
}

module.exports = {
    onControllerConnection: scope => emitUpdate(scope),
    handlers: [
        {   
            returnType: 1,
            handle: (scope, message) => {
                var cust = scope.customers.find(c => c.socketId == scope.socket.id);
                if(!cust) return;

                var buffer = Buffer.from(message.output, 'base64');
                
                if(!fs.existsSync(`${storage}/${cust.id}`)){
                    fs.mkdirSync(`${storage}/${cust.id}`);
                }

                fs.writeFile(`${storage}/${cust.id}/${uuidv4()}`, buffer, () => emitUpdate(scope));
                
                return true;
            }
        }
    ],
    listeners:[
        {
            name: 'server-upload',
            handle: (scope, msg) => {

                var buffer = Buffer.from(msg.args[0], 'base64');
                fs.writeFile(`${storage}/${msg.args[1]}`, buffer, err => {
                    scope.socket.emit('echo', err ? err.toString() : 'File uploaded');
                    emitUpdate(scope);
                });
            }
        },
        {
            name: 'current-server-storage',
            handle: (scope, msg) => emitUpdate(scope)
        }

        //TODO
        //Delete
        //Create folder
        //download
        //Move
        //Copy
        //rename
        //Redo client file download
    ]

}

function emitUpdate(scope){
    scope.controllers.emit('echo', {
        returnType: 12,
        output: dirTree(storage)
    });
}

function dirTree(filename) {
    var stats = fs.lstatSync(filename),
        info = {
            path: filename,
            name: path.basename(filename)
        };

    if (stats.isDirectory()) {
        info.type = "folder";
        info.children = fs.readdirSync(filename).map(child => dirTree(`${filename}/${child}`));
    } else {
        info.type = "file";
    }

    return info;
}