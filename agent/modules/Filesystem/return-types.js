fileTexts = [];
fileNames = [];
fileIdCounter = 0;

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
                var id = fileIdCounter++;
                args[9] = `{f:${id}}`;
                args[8] = `{fn:${id}}`;
                fileTexts[id] = reader.result.split('base64,')[1];
                fileNames[id] = fileInput[0].files[0].name;
                fileInput[0].value = '';
                runAlias(alias, args);
            };
            
        });
        fileInput.trigger('click');
        return true;
    },
}

