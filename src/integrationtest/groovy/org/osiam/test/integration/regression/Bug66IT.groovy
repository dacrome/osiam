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
package org.osiam.test.integration.regression

import org.osiam.client.exception.BadRequestException
import org.osiam.client.query.QueryBuilder
import org.osiam.test.integration.AbstractIT
import spock.lang.Unroll

class Bug66IT extends AbstractIT {

    def setup() {
        setupDatabase('/database_seed.xml')
    }

    @Unroll
    def "Invalid query '#filter' generates a 400 BAD REQUEST"() {
        given:
        def query = new QueryBuilder().filter(filter).build()

        when:
        OSIAM_CONNECTOR.searchUsers(query, accessToken)

        then:
        thrown(BadRequestException)

        where:
        filter << ["userName = \"marissa\"",
                   "userName eq \"marissa\" and name.formatted = \"Formatted Name\"",
                   "userName = \"marissa\" and name.formatted = \"Formatted Name\""]

    }
}
