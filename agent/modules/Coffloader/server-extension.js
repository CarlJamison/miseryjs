const bof_pack = require('./bof_pack.js')

module.exports = {
    handlers: [],
    listeners:[
        {
            name: 'coffloader',
            handle: (scope, msg) => {
                if(!msg.args.length){
                    scope.socket.emit('echo', 'Invalid args');
                }

                var cust = scope.customers.find(c => c.id == msg.id);

                if(cust){
                    if(msg.args[1]){
                        msg.args.pop();  //TODO this is bad
                        var pack = bof_pack(msg.args[1], msg.args.slice(2));

                        //TODO make this an exception and send it back to the user
                        if(pack){
                            scope.clients.to(cust.socketId).emit("run-task", ["Coffloader", msg.args[0], pack.toString('base64')]);
                        }else{
                            scope.socket.emit('echo', 'Bof Pack Error');
                        }
                        

                    }else{
                        scope.clients.to(cust.socketId).emit("run-task", ["Coffloader", msg.args[0]]);
                    }
                }
            }
        }
    ]

}