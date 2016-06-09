/**
 * The MIT License (MIT)
 *
 * Copyright (C) 2013-2016 tarent solutions GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.osiam.auth.login.ldap;

import com.google.common.base.Strings;
import org.osiam.scim.extension.OsiamExtension;
import org.osiam.auth.exception.LdapConfigurationException;
import org.osiam.configuration.LdapAuthentication;
import org.osiam.resources.scim.Address;
import org.osiam.resources.scim.Email;
import org.osiam.resources.scim.Entitlement;
import org.osiam.resources.scim.Extension;
import org.osiam.resources.scim.Im;
import org.osiam.resources.scim.Name;
import org.osiam.resources.scim.PhoneNumber;
import org.osiam.resources.scim.Photo;
import org.osiam.resources.scim.Role;
import org.osiam.resources.scim.User;
import org.osiam.resources.scim.X509Certificate;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class OsiamLdapUserContextMapper extends LdapUserDetailsMapper {

    private final ScimToLdapAttributeMapping scimLdapAttributes;

    public OsiamLdapUserContextMapper(ScimToLdapAttributeMapping scimToLdapAttributeMapping) {
        this.scimLdapAttributes = scimToLdapAttributeMapping;
    }

    public User mapUser(DirContextOperations ldapUserData) {

        Extension extension = new Extension.Builder(OsiamExtension.URN)
                .setField("origin", LdapAuthentication.LDAP_PROVIDER)
                .build();

        String userName = ldapUserData.getStringAttribute(scimLdapAttributes.toLdapAttribute("userName"));
        User.Builder builder = new User.Builder(userName)
                .addExtension(extension)
                .setActive(true)
                .setPassword(UUID.randomUUID().toString() + UUID.randomUUID().toString());

        for (String scimAttribute : scimLdapAttributes.scimAttributes()) {
            String ldapAttribute = scimLdapAttributes.toLdapAttribute(scimAttribute);
            String ldapValue = ldapUserData.getStringAttribute(ldapAttribute);

            if (Strings.isNullOrEmpty(ldapValue)) {
                continue;
            }

            switch (scimAttribute) {
            case "userName":
                break;
            case "displayName":
                builder.setDisplayName(ldapValue);
                break;
            case "email":
                Email.Builder emailBuilder = new Email.Builder().setValue(ldapValue)
                        .setType(new Email.Type(LdapAuthentication.LDAP_PROVIDER));
                List<Email> emails = new ArrayList<>();
                emails.add(emailBuilder.build());
                builder.addEmails(emails);
                break;
            case "entitlement":
                Entitlement.Builder entitlementBuilder = new Entitlement.Builder().setValue(ldapValue)
                        .setType(new Entitlement.Type(LdapAuthentication.LDAP_PROVIDER));
                List<Entitlement> entitlements = new ArrayList<>();
                entitlements.add(entitlementBuilder.build());
                builder.addEntitlements(entitlements);
                break;
            case "externalId":
                builder.setExternalId(ldapValue);
                break;
            case "im":
                Im.Builder imBuilder = new Im.Builder().setValue(ldapValue)
                        .setType(new Im.Type(LdapAuthentication.LDAP_PROVIDER));
                List<Im> ims = new ArrayList<>();
                ims.add(imBuilder.build());
                builder.addIms(ims);
                break;
            case "locale":
                builder.setLocale(ldapValue);
                break;
            case "nickName":
                builder.setNickName(ldapValue);
                break;
            case "phoneNumber":
                PhoneNumber.Builder phoneNumberBuilder = new PhoneNumber.Builder().setValue(ldapValue)
                        .setType(new PhoneNumber.Type(LdapAuthentication.LDAP_PROVIDER));
                List<PhoneNumber> phoneNumbers = new ArrayList<>();
                phoneNumbers.add(phoneNumberBuilder.build());
                builder.addPhoneNumbers(phoneNumbers);
                break;
            case "photo":
                Photo.Builder photoBuilder;
                try {
                    photoBuilder = new Photo.Builder().setValue(new URI(ldapValue))
                            .setType(new Photo.Type(LdapAuthentication.LDAP_PROVIDER));
                    List<Photo> photos = new ArrayList<>();
                    photos.add(photoBuilder.build());
                    builder.addPhotos(photos);
                } catch (URISyntaxException e) {
                    throw new LdapConfigurationException("Could not map the ldap attibute '"
                            + ldapAttribute + "' with the value '" + ldapValue
                            + "' into an scim photo because the value could not be conferted into an URI.", e);
                }
                break;
            case "preferredLanguage":
                builder.setPreferredLanguage(ldapValue);
                break;
            case "profileUrl":
                builder.setProfileUrl(ldapValue);
                break;
            case "role":
                Role.Builder roleBuilder = new Role.Builder().setValue(ldapValue)
                        .setType(new Role.Type(LdapAuthentication.LDAP_PROVIDER));
                List<Role> roles = new ArrayList<>();
                roles.add(roleBuilder.build());
                builder.addRoles(roles);
                break;
            case "timezone":
                builder.setTimezone(ldapValue);
                break;
            case "title":
                builder.setTitle(ldapValue);
                break;
            case "userType":
                builder.setUserType(ldapValue);
                break;
            case "x509Certificate":
                X509Certificate.Builder x509CertificateBuilder = new X509Certificate.Builder().setValue(ldapValue)
                        .setType(new X509Certificate.Type(LdapAuthentication.LDAP_PROVIDER));
                List<X509Certificate> x509Certificates = new ArrayList<>();
                x509Certificates.add(x509CertificateBuilder.build());
                builder.addX509Certificates(x509Certificates);
                break;
            default:
                if (!scimAttribute.startsWith("address.") && !scimAttribute.startsWith("name.")) {
                    throw createAttributeNotRecognizedException(scimAttribute);
                }
                break;
            }
        }

        builder.addAddresses(getAddresses(ldapUserData));
        builder.setName(getName(ldapUserData));

        return builder.build();
    }

    public User mapUser(User user, DirContextOperations ldapUserData) {

        User.Builder userBuilder = new User.Builder(user);

        for (String scimAttribute : scimLdapAttributes.scimAttributes()) {
            String ldapValue = ldapUserData.getStringAttribute(scimLdapAttributes.toLdapAttribute(scimAttribute));

            if (ldapValue == null) {
                ldapValue = "";
            }

            switch (scimAttribute) {
            case "userName":
                break;
            case "displayName":
                userBuilder.setDisplayName(ldapValue);
                break;
            case "email":
                updateEmail(userBuilder, user.getEmails(), ldapValue);
                break;
            case "entitlement":
                updateEntitlement(userBuilder, user.getEntitlements(), ldapValue);
                break;
            case "externalId":
                userBuilder.setExternalId(ldapValue);
                break;
            case "im":
                updateIm(userBuilder, user.getIms(), ldapValue);
                break;
            case "locale":
                userBuilder.setLocale(ldapValue);
                break;
            case "nickName":
                userBuilder.setNickName(ldapValue);
                break;
            case "phoneNumber":
                updatePhoneNumber(userBuilder, user.getPhoneNumbers(), ldapValue);
                break;
            case "photo":
                updatePhoto(userBuilder, user.getPhotos(), ldapValue, scimAttribute);
                break;
            case "preferredLanguage":
                userBuilder.setPreferredLanguage(ldapValue);
                break;
            case "profileUrl":
                userBuilder.setProfileUrl(ldapValue);
                break;
            case "role":
                updateRole(userBuilder, user.getRoles(), ldapValue);
                break;
            case "timezone":
                userBuilder.setTimezone(ldapValue);
                break;
            case "title":
                userBuilder.setTitle(ldapValue);
                break;
            case "userType":
                userBuilder.setUserType(ldapValue);
                break;
            case "x509Certificate":
                updateX509Certificate(userBuilder, user.getX509Certificates(), ldapValue);
                break;
            default:
                if (!scimAttribute.startsWith("address.") && !scimAttribute.startsWith("name.")) {
                    throw createAttributeNotRecognizedException(scimAttribute);
                }
            }
        }

        updateAddress(userBuilder, user.getAddresses(), ldapUserData);
        updateName(user.getName(), userBuilder, ldapUserData);

        return userBuilder.build();
    }

    private LdapConfigurationException createAttributeNotRecognizedException(String scimAttribute){
        return new LdapConfigurationException("The LDAP attribute mapping value '" + scimAttribute
                + "' could not be recognized as scim attribute.");
    }

    private void updateName(Name name, User.Builder userBuilder, DirContextOperations ldapUserData) {
        userBuilder.setName(getName(ldapUserData));
    }

    private void updateAddress(User.Builder updateBuilder, List<Address> addresses,
            DirContextOperations ldapUserData) {
        for (Address address : addresses) {
            if (address.getType() != null && address.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteAddress(address);
            }
        }

        List<Address> newAddresses = getAddresses(ldapUserData);
        if (!newAddresses.isEmpty()) {
            updateBuilder.addAddress(newAddresses.get(0));
        }
    }

    private void updateEmail(UpdateUser.Builder updateBuilder, List<Email> emails, String emailValue) {
        Email newEmail = new Email.Builder().setValue(emailValue)
                .setType(new Email.Type(LdapAuthentication.LDAP_PROVIDER)).build();
        for (Email email : emails) {
            if (email.getType() != null && email.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteEmail(email);
            }
        }
        updateBuilder.addEmail(newEmail);
    }

    private void updateEntitlement(UpdateUser.Builder updateBuilder, List<Entitlement> entitlements, String value) {
        Entitlement newEntitlement = new Entitlement.Builder().setValue(value)
                .setType(new Entitlement.Type(LdapAuthentication.LDAP_PROVIDER)).build();
        for (Entitlement entitlement : entitlements) {
            if (entitlement.getType() != null
                    && entitlement.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteEntitlement(entitlement);
            }
        }
        updateBuilder.addEntitlement(newEntitlement);
    }

    private void updateIm(UpdateUser.Builder updateBuilder, List<Im> ims, String value) {
        Im newIm = new Im.Builder().setValue(value).setType(new Im.Type(LdapAuthentication.LDAP_PROVIDER)).build();
        for (Im im : ims) {
            if (im.getType() != null && im.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteIm(im);
            }
        }
        updateBuilder.addIm(newIm);
    }

    private void updatePhoneNumber(UpdateUser.Builder updateBuilder, List<PhoneNumber> phoneNumbers, String value) {
        PhoneNumber newPhoneNumber = new PhoneNumber.Builder().setValue(value)
                .setType(new PhoneNumber.Type(LdapAuthentication.LDAP_PROVIDER)).build();
        for (PhoneNumber phoneNumber : phoneNumbers) {
            if (phoneNumber.getType() != null
                    && phoneNumber.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deletePhoneNumber(phoneNumber);
            }
        }
        updateBuilder.addPhoneNumber(newPhoneNumber);
    }

    private void updatePhoto(UpdateUser.Builder updateBuilder, List<Photo> photos, String value, String scimAttribute) {
        try {
            for (Photo photo : photos) {
                if (photo.getType() != null && photo.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                    updateBuilder.deletePhoto(photo);
                }
            }
            if (value.length() > 0) {
                Photo newPhoto = new Photo.Builder()
                        .setValue(new URI(value))
                        .setType(new Photo.Type(LdapAuthentication.LDAP_PROVIDER))
                        .build();
                updateBuilder.addPhoto(newPhoto);
            }
        } catch (URISyntaxException e) {
            throw new LdapConfigurationException("Could not map the ldap attibute '"
                    + scimLdapAttributes.toLdapAttribute(scimAttribute) + "' with the value '" + value
                    + "' into an scim photo because the value could not be converted into an URI.", e);
        }
    }

    private void updateRole(UpdateUser.Builder updateBuilder, List<Role> roles, String value) {
        Role newRole = new Role.Builder().setValue(value).setType(new Role.Type(LdapAuthentication.LDAP_PROVIDER))
                .build();
        for (Role role : roles) {
            if (role.getType() != null && role.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteRole(role);
            }
        }
        updateBuilder.addRole(newRole);
    }

    private void updateX509Certificate(UpdateUser.Builder updateBuilder, List<X509Certificate> x509Certificates,
            String value) {
        X509Certificate newX509Certificate = new X509Certificate.Builder().setValue(value)
                .setType(new X509Certificate.Type(LdapAuthentication.LDAP_PROVIDER)).build();
        for (X509Certificate x509Certificate : x509Certificates) {
            if (x509Certificate.getType() != null
                    && x509Certificate.getType().toString().equals(LdapAuthentication.LDAP_PROVIDER)) {
                updateBuilder.deleteX509Certificate(x509Certificate);
            }
        }
        updateBuilder.addX509Certificate(newX509Certificate);
    }

    private List<Address> getAddresses(DirContextOperations ldapUserData) {
        List<Address> addresses = new ArrayList<>();
        Address.Builder builder = new Address.Builder();
        boolean addressFound = false;

        for (String scimAttribute : scimLdapAttributes.scimAttributes()) {
            String ldapValue = ldapUserData.getStringAttribute(scimLdapAttributes.toLdapAttribute(scimAttribute));
            if (!scimAttribute.startsWith("address.")) {
                continue;
            }
            addressFound = true;
            switch (scimAttribute) {
            case "address.country":
                builder.setCountry(ldapValue);
                break;
            case "address.formatted":
                builder.setFormatted(ldapValue);
                break;
            case "address.locality":
                builder.setLocality(ldapValue);
                break;
            case "address.postalCode":
                builder.setPostalCode(ldapValue);
                break;
            case "address.region":
                builder.setRegion(ldapValue);
                break;
            case "address.streetAddress":
                builder.setStreetAddress(ldapValue);
                break;
            default:
                throw createAttributeNotRecognizedException(scimAttribute);
            }
        }

        if (addressFound) {
            builder.setType(new Address.Type(LdapAuthentication.LDAP_PROVIDER));
            addresses.add(builder.build());
        }
        return addresses;
    }

    private Name getName(DirContextOperations ldapUserData) {
        boolean nameFound = false;

        Name.Builder builder = mapName(ldapUserData, new Name.Builder());

        if (nameFound) {
            return builder.build();
        }
        return null;
    }

    private Name getName(DirContextOperations ldapUserData, Name name) {
        Name.Builder builder = new Name.Builder()
                .setFamilyName(name.getFamilyName())
                .setFormatted(name.getFormatted())
                .setGivenName(name.getGivenName())
                .setHonorificPrefix(name.getHonorificPrefix())
                .setHonorificSuffix(name.getHonorificSuffix())
                .setMiddleName(name.getMiddleName());

        return mapName(ldapUserData, builder).build();
    }

    private Name.Builder mapName(DirContextOperations ldapUserData, Name.Builder nameBuilder) {
        for (String scimAttribute : scimLdapAttributes.scimAttributes()) {
            String ldapValue = ldapUserData.getStringAttribute(scimLdapAttributes.toLdapAttribute(scimAttribute));
            if (!scimAttribute.startsWith("name.")) {
                continue;
            }
            switch (scimAttribute) {
                case "name.familyName":
                    nameBuilder.setFamilyName(ldapValue);
                    break;
                case "name.formatted":
                    nameBuilder.setFormatted(ldapValue);
                    break;
                case "name.givenName":
                    nameBuilder.setGivenName(ldapValue);
                    break;
                case "name.honorificPrefix":
                    nameBuilder.setHonorificPrefix(ldapValue);
                    break;
                case "name.honorificSuffix":
                    nameBuilder.setHonorificSuffix(ldapValue);
                    break;
                case "name.middleName":
                    nameBuilder.setMiddleName(ldapValue);
                    break;
                default:
                    throw createAttributeNotRecognizedException(scimAttribute);
            }
        }
        return nameBuilder;
    }
}
