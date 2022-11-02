types = {
    ...types,
    11: message => {

        var contentHandle = $(".key-logger-content");
        if(!contentHandle.length){

            createTab("Key Logger", '<div class="key-logger-content"></div>');
            contentHandle = $(".key-logger-content");
        }

        contentHandle.append($('<div/>').text(message.output).html());
    },
}

