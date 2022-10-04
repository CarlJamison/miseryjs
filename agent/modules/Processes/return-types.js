types = {
    ...types,
    4: message => {
        var label = "Processes",
        id = "tabs-" + tabCounter,
        li = $( tabTemplate.replace( /#\{href\}/g, "#" + id ).replace( /#\{label\}/g, label ) );

        var content = "";
        var list = JSON.parse(message.output);
        if(list.length){
            content = `<table><tr><th>${Object.keys(list[0]).join("</th><th>")}</th></tr>`;
            list.forEach(p => content += `<tr><td>${Object.values(p).join("</td><td>")}</tr></td>`);
            content += "</table>"
        }else{
            content = "Nothing to display";
        }

        tabs.find( ".ui-tabs-nav" ).append( li );
        tabs.prepend( "<div id='" + id + "'><p>" + content + "</p></div>" );
        tabs.tabs( "refresh" );

        tabCounter++;
    },
}

