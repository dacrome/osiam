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
package org.osiam.client.regression;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.osiam.client.AbstractIntegrationTestBase;
import org.osiam.client.oauth.Scope;
import org.osiam.client.query.Query;
import org.osiam.client.query.QueryBuilder;
import org.osiam.resources.scim.SCIMSearchResult;
import org.osiam.resources.scim.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseOperation;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import com.github.springtestdbunit.annotation.DatabaseTearDown;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/context.xml")
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class, DbUnitTestExecutionListener.class })
@DatabaseSetup(value = "/database_seeds/Bug251/database_seed.xml")
@DatabaseTearDown(value = "/database_tear_down.xml", type = DatabaseOperation.DELETE_ALL)
public class Bug251 extends AbstractIntegrationTestBase {

    @Before
    public void setup() {
        accessToken = OSIAM_CONNECTOR.retrieveAccessToken("marissa", "koala", Scope.ADMIN);
    }

    @Test
    public void sorting_by_formatted_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.formatted")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }

    @Test
    public void sorting_by_familyName_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.familyName")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }

    @Test
    public void sorting_by_givenName_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.givenName")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }

    @Test
    public void sorting_by_middleName_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.middleName")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }

    @Test
    public void sorting_by_honorificPrefix_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.honorificPrefix")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }

    @Test
    public void sorting_by_honorificSuffix_does_not_remove_users_without_a_name_set_from_result() {
        Query query = new QueryBuilder()
                .ascending("name.honorificSuffix")
                .build();

        SCIMSearchResult<User> result = OSIAM_CONNECTOR.searchUsers(query, accessToken);

        assertThat(result.getResources().size(), is(equalTo(2)));
    }
}
