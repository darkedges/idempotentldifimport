package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/darkedges/ldifimport/config"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

type ModifyModListOptions struct {
	OldEntry               *ldap.Entry
	NewEntry               *ldap.Entry
	ignore_attr_types      []string
	ignore_oldexistent     bool
	case_ignore_attr_types []string
	ModifyRequest          *ldap.ModifyRequest
}

func main() {
	var configFN string
	var ldifFN string
	flag.StringVar(&configFN, "config", "", "Location of configuration file")
	flag.StringVar(&ldifFN, "ldif", "", "Location of LDIF file")
	flag.Parse()

	if len(configFN) == 0 || len(ldifFN) == 0 {
		fmt.Println("Usage: ldifimport.go")
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfg, err := config.GetOptions(configFN)
	if err != nil {
		exitGracefully(fmt.Errorf("failed to get options. %s", err))
	}
	conn, err = connect(cfg)
	if err != nil {
		exitGracefully(fmt.Errorf("failed to bind. %s", err))
	}
	if err := parseLDIFFile(ldifFN, &LDIFOptions{Callback: callback}); err != nil {
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

func modifyModList(options *ModifyModListOptions) {
	oldEntryDictionary := convertToDictionary(options.OldEntry)
	newEntryDictionary := convertToDictionary(options.NewEntry)
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

func removeNulls(values []string) (value []string) {
	for _, item := range values {
		if item != "" {
			value = append(value, item)
		}
	}
	return
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
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

type LDIFOptions struct {
	Callback func(*ldif.Entry)
}

var conn *ldap.Conn

func callback(entry *ldif.Entry) {
	changeType := "add"
	var attributes []string
	for _, i := range entry.Entry.Attributes {
		if i.Name == "changetype" {
			changeType = i.Values[0]
		}
		attributes = append(attributes, i.Name)
	}
	searchRequest := ldap.NewSearchRequest(
		entry.Entry.DN,
		ldap.ScopeBaseObject, ldap.DerefAlways, 0, 0, false,
		"(objectclass=*)",
		attributes,
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
	if len(sr.Entries) > 0 {
		switch changeType {
		case "delete":
			delRequest := ldap.NewDelRequest(
				entry.Entry.DN,
				nil,
			)
			err = conn.Del(delRequest)
			if err != nil {
				exitGracefully(fmt.Errorf("failed to delete entry. %s", err))
			}
		case "add":
			modifyRequest := ldap.NewModifyRequest(entry.Entry.DN, nil)
			modifyModList(&ModifyModListOptions{OldEntry: sr.Entries[0], NewEntry: entry.Entry, ModifyRequest: modifyRequest})
			if len(modifyRequest.Changes) > 0 {
				err = conn.Modify(modifyRequest)
				if err != nil {
					exitGracefully(fmt.Errorf("failed to modify entry. %s", err))
				}
			}
		}
	} else {
		if objectNotFound {
			addRequest := ldap.NewAddRequest(entry.Entry.DN, nil)
			for _, v := range entry.Entry.Attributes {
				addRequest.Attribute(v.Name, v.Values)
			}
			if err := conn.Add(addRequest); err != nil {
				exitGracefully(fmt.Errorf("failed to add entry. %s", err))
			}
		}
	}
}

func parseLDIFFile(fn string, options *LDIFOptions) error {
	r, err := os.Open(fn)
	if err != nil {
		return fmt.Errorf("failed to open. %s", err)
	}
	err = ldif.ParseWithCallback(r, options.Callback)
	return err
}
