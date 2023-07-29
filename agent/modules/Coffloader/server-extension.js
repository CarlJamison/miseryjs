const bof_pack = require('./bof_pack.js')

module.exports = {
    listeners:[
        {
            name: 'coffloader',
            handle: (scope, msg) => {
                if(!msg.args.length)
                    scope.socket.emit('echo', 'Invalid args');

                var cust = scope.customers.find(c => c.id == msg.id);

                if(cust){

                    if(msg.args[1]){

                        try{
                            var pack = bof_pack(msg.args[1], msg.args.slice(2));
                            scope.clients.to(cust.socketId)
                                .emit("run-task", ["Coffloader", msg.args[0], pack.toString('base64')]);
                        }catch(error){
                            scope.socket.emit('echo', error);
                        }                        

                    }else{
                        scope.clients.to(cust.socketId).emit("run-task", ["Coffloader", msg.args[0]]);
                    }
                }
            }
        }
    ]
}