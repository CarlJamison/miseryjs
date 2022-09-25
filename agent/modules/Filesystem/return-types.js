transforms = {
    ...transforms,
    file_select: (alias, args) => {
        var fileInput = $('#file');
        var hasSent = false;
        fileInput[0].addEventListener('input', file => {
            if(hasSent) return;
            hasSent = true;
            var reader = new FileReader();
            reader.readAsDataURL(fileInput[0].files[0]);
            
            reader.onload = () => {
                args[9] = reader.result.split('base64,')[1];
                fileInput[0].value = '';
                runAlias(alias, args);
            };
            
        });
        fileInput.trigger('click');
        return true;
    },
}

