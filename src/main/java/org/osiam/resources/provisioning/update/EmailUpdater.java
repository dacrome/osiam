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
package org.osiam.resources.provisioning.update;

import com.google.common.base.Strings;
import org.osiam.resources.converter.EmailConverter;
import org.osiam.resources.scim.Email;
import org.osiam.storage.entities.EmailEntity;
import org.osiam.storage.entities.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

/**
 * The EmailUpdater provides the functionality to update the {@link EmailEntity} of a UserEntity
 */
@Service
class EmailUpdater {

    private final EmailConverter emailConverter;

    @Autowired
    public EmailUpdater(EmailConverter emailConverter) {
        this.emailConverter = emailConverter;
    }

    /**
     * updates (adds new, delete, updates) the {@link EmailEntity}'s of the given {@link UserEntity} based on the given
     * List of Email's
     *
     * @param emails     list of Email's to be deleted, updated or added
     * @param userEntity user who needs to be updated
     * @param attributes all {@link EmailEntity}'s will be deleted if this Set contains 'emails'
     */
    void update(List<Email> emails, UserEntity userEntity, Set<String> attributes) {

        if (attributes.contains("emails")) {
            userEntity.removeAllEmails();
        }

        if (emails != null) {
            for (Email scimEmail : emails) {
                EmailEntity emailEntity = emailConverter.fromScim(scimEmail);
                userEntity.removeEmail(emailEntity); // we always have to remove the email in case
                // the primary attribute has changed
                if (Strings.isNullOrEmpty(scimEmail.getOperation())
                        || !scimEmail.getOperation().equalsIgnoreCase("delete")) {

                    ensureOnlyOnePrimaryEmailExists(emailEntity, userEntity.getEmails());
                    userEntity.addEmail(emailEntity);
                }
            }
        }
    }

    /**
     * if the given newEmail is set to primary the primary attribute of all existing email's in the {@link UserEntity}
     * will be removed
     *
     * @param newEmail to be checked if it is primary
     * @param emails   all existing email's of the {@link UserEntity}
     */
    private void ensureOnlyOnePrimaryEmailExists(EmailEntity newEmail, Set<EmailEntity> emails) {
        if (newEmail.isPrimary()) {
            for (EmailEntity exisitngEmailEntity : emails) {
                if (exisitngEmailEntity.isPrimary()) {
                    exisitngEmailEntity.setPrimary(false);
                }
            }
        }
    }
}