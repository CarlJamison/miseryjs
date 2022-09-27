types = {
    ...types,
    4: message => {
        var label = "Processes",
        id = "tabs-" + tabCounter,
        li = $( tabTemplate.replace( /#\{href\}/g, "#" + id ).replace( /#\{label\}/g, label ) ),
        tabContentHtml = message.output;

        tabs.find( ".ui-tabs-nav" ).append( li );
        tabs.prepend( "<div id='" + id + "'><p>" + tabContentHtml + "</p></div>" );
        tabs.tabs( "refresh" );

        tabCounter++;
    },
}

