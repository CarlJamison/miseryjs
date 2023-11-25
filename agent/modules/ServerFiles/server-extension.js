const fs = require('fs');
const path = require('path');
const storage = "file_storage"

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

                message.output = JSON.parse(message.output);
                var buffer = Buffer.from(message.output.data, 'base64');
                
                if(!fs.existsSync(`${storage}/${cust.id}`)){
                    fs.mkdirSync(`${storage}/${cust.id}`);
                }

                fs.writeFile(`${storage}/${cust.id}/${message.output.name}`, buffer, () => emitUpdate(scope));
                
                return true;
            }
        }
    ],
    listeners:[
        {
            name: 'server-upload',
            handle: (scope, msg) => {

                var buffer = Buffer.from(msg.args[0], 'base64');
                
                var dirPath = msg.args[2];
                if(fs.existsSync(dirPath)){
                    if(!fs.lstatSync(dirPath).isDirectory()) dirPath = path.dirname(msg.args[2]);
                }else{
                    dirPath = null
                }

                msg.args[2] = path.basename(path.dirname(msg.args[2]));

                fs.writeFile(`${dirPath ? dirPath : storage}/${msg.args[1]}`, buffer, err => {
                    scope.socket.emit('echo', err ? err.toString() : 'File uploaded');
                    emitUpdate(scope);
                });
            }
        },
        {
            name: 'server-download',
            handle: (scope, msg) => {
                fs.readFile(msg.args[0], (err, data) => {
                    if(err){
                        scope.socket.emit('echo', {
                            returnType: 0,
                            output: err.toString()
                        });
                    }else{
                        scope.socket.emit('echo', {
                            returnType: 1,
                            output:  {
                                name: path.basename(msg.args[0]),
                                data: data.toString('base64')
                            }
                        });
                    }
                });
            }
        },
        {
            name: 'delete-file',
            handle: (scope, msg) => {
                fs.unlink(msg.args[0], err => {
                    if(err){
                        scope.socket.emit('echo', {
                            returnType: 0,
                            output: err.toString()
                        });
                    }else{
                        emitUpdate(scope);
                    }
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