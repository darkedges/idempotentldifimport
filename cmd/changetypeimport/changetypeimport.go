package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/darkedges/ldifcmd/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

var conn *ldap.Conn

type LDIFOptions struct {
	Callback func(*ldif.Entry)
}

type ModifyModListOptions struct {
	OldEntry               *ldap.Entry
	NewEntry               *ldap.AddRequest
	ignore_attr_types      []string
	ignore_oldexistent     bool
	case_ignore_attr_types []string
	ModifyRequest          *ldap.ModifyRequest
}

func main() {
	flag.Parse()

	if config.Flags.PrintVersion {
		config.PrintVersion()
		return
	}

	if len(config.Flags.ConfigFN) == 0 || len(config.Flags.LdifFN) == 0 {
		fmt.Println("Usage: changetypeimport")
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfg, err := config.GetOptions(config.Flags.ConfigFN)
	if err != nil {
		exitGracefully(fmt.Errorf("failed to get options. %s", err))
	}

	conn, err = connect(cfg)
	if err != nil {
		exitGracefully(fmt.Errorf("failed to bind. %s", err))
	}

	if err := parseLDIFFile(config.Flags.LdifFN, &LDIFOptions{Callback: callback}); err != nil {
		exitGracefully(fmt.Errorf("failed to parse ldif. %s", err))
	}
	conn.Close()

}

func exitGracefully(err error) {
	fmt.Printf("Error: %v", err)
	os.Exit(1)
}

func connect(cfg config.Config) (conn *ldap.Conn, err error) {
	url := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err = ldap.DialTLS("tcp", url, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("failed to connect. %s", err)
	}

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind. %s", err)
	}
	return
}

func parseLDIFFile(fn string, options *LDIFOptions) error {
	r, err := os.Open(fn)
	if err != nil {
		return fmt.Errorf("failed to open. %s", err)
	}
	err = ldif.ParseWithCallback(r, options.Callback)
	return err
}

func callback(entry *ldif.Entry) {
	var operation string
	var DN string
	if entry.Add != nil {
		operation = "add"
		DN = entry.Add.DN
	}
	if entry.Del != nil {
		operation = "delete"
		DN = entry.Del.DN
	}
	if entry.Modify != nil {
		operation = "modify"
		DN = entry.Modify.DN
	}
	searchRequest := ldap.NewSearchRequest(
		DN,
		ldap.ScopeBaseObject, ldap.DerefAlways, 0, 0, false,
		"(objectclass=*)",
		nil,
		nil)
	sr, err := conn.Search(searchRequest)
	objectNotFound := false
	if err != nil {
		if strings.HasPrefix(err.Error(), "LDAP Result Code 32") {
			objectNotFound = true
		} else {
			exitGracefully(fmt.Errorf("ldap failed. %s", err))
		}
	}
	if !objectNotFound && len(sr.Entries) == 1 {
		srentry := sr.Entries[0]
		// We have an entry, so lets work out what to do with it
		if operation == "delete" {
			verbose("Delete: %s", DN)
			if err := conn.Del(entry.Del); err != nil {
				exitGracefully(fmt.Errorf("failed to add entry. %s", err))
			}
		}
		if operation == "add" {
			verbose("Already Added: %s\n", DN)
			modifyRequest := ldap.NewModifyRequest(DN, nil)
			ModifyModList(&ModifyModListOptions{OldEntry: srentry, NewEntry: entry.Add, ModifyRequest: modifyRequest})
			if len(modifyRequest.Changes) > 0 {
				verbose("\tUpdated: %s\n", DN)
				err = conn.Modify(modifyRequest)
				if err != nil {
					exitGracefully(fmt.Errorf("failed to modify entry. %s", err))
				}
			}
		}
		if operation == "modify" {
			verbose("Modify: %s\n", DN)
			modifyRequest := ldap.NewModifyRequest(DN, nil)
			for _, v := range entry.Modify.Changes {
				switch v.Operation {
				case 0:
					var addVals []string
					v2 := srentry.GetEqualFoldAttributeValues(v.Modification.Type)
					if len(v2) > 0 {
						for _, val := range v.Modification.Vals {
							if !stringInSlice(val, v2) {
								addVals = append(addVals, val)
							}
						}
					}
					if len(addVals) > 0 {
						verbose("\tadd modify operation: %s\n", v.Modification.Type)
						verbose("\t\t%s\n", addVals)
						modifyRequest.Replace(v.Modification.Type, addVals)
						// Need to load schema to find if the attribute is single or multi value
						//modifyRequest.Add(v.Modification.Type, addVals)
					}
				case 1:
					var deleteVals []string
					v2 := srentry.GetEqualFoldAttributeValues(v.Modification.Type)
					if len(v2) > 0 {
						for _, val := range v.Modification.Vals {
							if stringInSlice(val, v2) {
								deleteVals = append(deleteVals, val)
							}
						}
					}
					if len(deleteVals) > 0 {
						verbose("\tdelete modify operation: %s\n", v.Modification.Type)
						verbose("\t\t%s\n", deleteVals)
						modifyRequest.Delete(v.Modification.Type, deleteVals)
					}
				case 2:
					v2 := srentry.GetEqualFoldAttributeValues(v.Modification.Type)
					deleteVals := difference(v2, v.Modification.Vals)
					if len(deleteVals) > 0 {
						verbose("\tdelete modify operation: %s\n", v.Modification.Type)
						verbose("\t\t%s\n", deleteVals)
						modifyRequest.Delete(v.Modification.Type, deleteVals)
					}
					addVals := difference(v.Modification.Vals, v2)
					if len(addVals) > 0 {
						verbose("\tadd modify operation: %s\n", v.Modification.Type)
						verbose("\t\t%s\n", addVals)
						modifyRequest.Add(v.Modification.Type, addVals)
					}
				default:
					verbose("unknown modify operation")
				}
			}
			if len(modifyRequest.Changes) > 0 {
				verbose("\tModified: %s", DN)
				if err := conn.Modify(modifyRequest); err != nil {
					exitGracefully(fmt.Errorf("failed to add entry. %s", err))
				}
			}
		}
	} else {
		if operation == "modify" {
			verbose("Cannot modify '%s' as it is Deleted.", DN)
		}
		if operation == "delete" {
			verbose("Already Deleted: %s", DN)
		}
		if operation == "add" {
			verbose("Added: %s", DN)
			if err := conn.Add(entry.Add); err != nil {
				exitGracefully(fmt.Errorf("failed to add entry. %s", err))
			}
		}
	}
}

func verbose(a string, b ...interface{}) {
	if config.Flags.Verbose {
		fmt.Printf(a, b...)
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func removeNulls(values []string) (value []string) {
	for _, item := range values {
		if item != "" {
			value = append(value, item)
		}
	}
	return
}

func toLower(valuesArray []string) []string {
	values := valuesArray
	for i, val := range values {
		values[i] = strings.ToLower(val)
	}
	return values
}

func convertToDictionary(entry *ldap.Entry) (m map[string][]string) {
	m = make(map[string][]string)
	for _, key := range entry.Attributes {
		m[key.Name] = key.Values
	}
	return
}

func convertToDictionary2(entry *ldap.AddRequest) (m map[string][]string) {
	m = make(map[string][]string)
	for _, key := range entry.Attributes {
		m[key.Type] = key.Vals
	}
	return
}

func ModifyModList(options *ModifyModListOptions) {
	oldEntryDictionary := convertToDictionary(options.OldEntry)
	newEntryDictionary := convertToDictionary2(options.NewEntry)
	ignore_attr_types := toLower(options.ignore_attr_types)
	// var modlist []string
	var attrtype_lower_map = make(map[string]string)

	for k := range oldEntryDictionary {
		attrtype_lower_map[strings.ToLower(k)] = k
	}
	for attrtype, value := range newEntryDictionary {
		var attrtype_lower = strings.ToLower(attrtype)
		if stringInSlice(attrtype_lower, ignore_attr_types) {
			// This attribute type is ignored
			continue
		}
		// Filter away null-strings
		var new_value = removeNulls(value)
		var old_value []string
		if _, ok := attrtype_lower_map[attrtype_lower]; ok {
			old_value = removeNulls(oldEntryDictionary[attrtype_lower_map[attrtype_lower]])
			delete(attrtype_lower_map, attrtype_lower)
		} else {
			old_value = []string{}
		}
		if len(old_value) == 0 && len(new_value) > 0 {
			// Add a new attribute to entry
			options.ModifyRequest.Add(attrtype, new_value)
		} else if len(old_value) > 0 && len(new_value) > 0 {
			// Replace existing attribute
			var replace_attr_value = false
			old_value_set := old_value
			new_value_set := new_value
			if stringInSlice(attrtype_lower, options.case_ignore_attr_types) {
				old_value_set = toLower(old_value_set)
				new_value_set = toLower(new_value_set)
			}
			sort.Strings(old_value_set)
			sort.Strings(new_value_set)
			if !reflect.DeepEqual(old_value_set, new_value_set) {
				replace_attr_value = true
			}
			if replace_attr_value {
				options.ModifyRequest.Replace(attrtype, new_value)
			}
		} else if len(old_value) > 0 && len(new_value) == 0 {
			// Completely delete an existing attribute
			options.ModifyRequest.Delete(attrtype, []string{})
		}
	}
	if !options.ignore_oldexistent {
		// Remove all attributes of old_entry which are not present in new_entry at all
		for attrtype := range attrtype_lower_map {
			if stringInSlice(attrtype, ignore_attr_types) {
				// This attribute type is ignored
				continue
			}
			options.ModifyRequest.Delete(attrtype, []string{})
		}
	}
}
