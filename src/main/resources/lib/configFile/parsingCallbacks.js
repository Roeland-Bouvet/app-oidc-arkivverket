
exports.parseStringArray = (jsonStringValue) => {
    if (!jsonStringValue) {
        return [];
    }

    let parsed;
    try {
        parsed = JSON.parse((jsonStringValue || '').trim());
    } catch (e) {
        throw Error(`Expected a well-formed JSON string: '${jsonStringValue}'`, e);
    }

    if (!parsed) {
        return [];
    }
    if (!Array.isArray(parsed)) {
        throw Error(`Expected a well-formed array: ${JSON.stringify(parsed)}`);
    }

    return parsed.map((item, i) => {
        if ('string' !== typeof item) {
            throw Error(`Item with index ${i} in the array is not a string: ${JSON.stringify(item)}`);
        }
        return item.trim();
    })
}

exports.firstAtsToDollar = (value) => (value || '').replace(/@@\{/, '${');



// Keys below are converted to regexpattern-ready strings for detecting all .cfg keys matching 'idprovider.<idprovidername>.<key>'.
// For example, "defaultGroups" below is converted to '^idprovider\.[a-zA-Z0-9_-]+\.defaultGroups$' which will match the keys
// 'idprovider.oidc.defaultGroups' and 'idprovider.other.defaultGroups' in the config file, but not 'idprovider.oidc.tokenUrl'.
const IDPROVIDER_PARSE_CALLBACKS = {
    'defaultGroups': exports.parseStringArray,
    'scopes':  (value) => exports.parseStringArray(value).join(" "),
    'mappings.displayName': exports.atsToDollar,
    'mappings.email': exports.atsToDollar
}



// Magic: make regex-pattern-ready keys for the final object and export it
const RX_SUBFIELD='[a-zA-Z0-9_-]+';
exports.PARSING_CALLBACKS = {};
Object.keys(IDPROVIDER_PARSE_CALLBACKS).forEach( key => {
    const rxKey = key.replace(/\./g, `\.`);
    exports.PARSING_CALLBACKS[`^idprovider\.${RX_SUBFIELD}\.${rxKey}$`] = IDPROVIDER_PARSE_CALLBACKS[key];
});
