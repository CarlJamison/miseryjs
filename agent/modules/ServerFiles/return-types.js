types = {
    ...types,
    12: message => {
        
        var content = `
        <div class=server-storage-content>
        <style>
            .server-storage-content{
                background-color: white-smoke;
                letter-spacing: 0.25px;
            }
            .clicked-file{
                background-color: #adf5ad;
                border: solid 1px #129d12;
            }
            .file:hover{
                background-color: #d7ffd7;
            }
            .file{
                padding: 4px;
                border-radius: 8px;
                cursor: pointer;
            }
            .file-button{
                flex: auto;
                font-size: xx-large;
                text-align: center;
                cursor: pointer;
                border-bottom: solid;
                padding-bottom: 12px;
            }
            .file-button:hover{
                color: #129d12;
            }
        </style>
        <div style="display:flex">
            <!--<span class="file-button material-symbols-outlined" onclick='createFolder()'>create_new_folder</span>
            <span class="file-button material-symbols-outlined" onclick='copyFile()'>create_new_folder</span>
            <span class="file-button material-symbols-outlined" onclick='renameFile()'>create_new_folder</span>-->
            <span class="file-button material-symbols-outlined" onclick='uploadFile()'>upload_file</span>
            <span class="file-button material-symbols-outlined" onclick='downloadFile()'>download</span>
            <span class="file-button material-symbols-outlined" onclick='deleteFile()'>delete</span>
        </div>
        ${getFileHtml(message.output)}
        </div>`;

        var contentHandle = $(".server-storage-content");

        if(!contentHandle.length){
            createTab("Server Storage", content);
        }else{
            contentHandle.html(content)
        }

    },
}

var selected_file = ""
var fileMap = [];
var idMap = [];

function getFileHtml(file, out = "", indent = "") {

    var className = fileMap[file.path];
    if(!className){
        fileMap[file.path] = className = uuidv4();
        idMap[className] = file.path;
    }

    var out = `<div id="${className}" class='file' onclick='toggle(\"${className}\")'>`;

    if(file.children && file.children.length){
        out += `<span id="icon-${className}" style="vertical-align: bottom" class="material-symbols-outlined">expand_more</span>`;
    }

    out += indent + file.name + "</div>";

    if (file.children) {
        file.children.map(child =>
            out += `<div class=${className} style="margin-left: 40px">${getFileHtml(child, out, indent + "\t")}</div>`
        );
    }

    return out;
}

function toggle(className){
    
    $( "." + className ).toggleClass("ui-helper-hidden");
    
    $( ".clicked-file" ).toggleClass("clicked-file");
    var isHidden = $( "." + className ).hasClass("ui-helper-hidden");
    $( "#icon-" + className ).html(isHidden ? "chevron_right" : "expand_more");
    $( "#" + className ).toggleClass("clicked-file");

    selected_file = className;
}

function uuidv4() {
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
      (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
}

function downloadFile(){
    var file = idMap[selected_file];
    
    if(file){
        terminal.exec(`extension server-download ${file}`, true)
    }
}

function uploadFile(){
    var file = idMap[selected_file];
    terminal.exec(`server-upload ${file}`, true)
}

function deleteFile(){
    var file = idMap[selected_file];
    if(file){
        terminal.exec(`extension delete-file ${file}`, true)
    }
}
  

