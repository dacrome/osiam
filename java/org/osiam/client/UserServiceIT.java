package org.osiam.client;

import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseOperation;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import com.github.springtestdbunit.annotation.DatabaseTearDown;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.osiam.client.exception.UnauthorizedException;
import org.osiam.resources.scim.MultiValuedAttribute;
import org.osiam.resources.scim.Name;
import org.osiam.resources.scim.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.isEmptyString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/context.xml")
@TestExecutionListeners({DependencyInjectionTestExecutionListener.class,
        DbUnitTestExecutionListener.class})
@DatabaseSetup("/database_seed.xml")
@DatabaseTearDown(value = "/database_seed.xml", type = DatabaseOperation.DELETE_ALL)
public class UserServiceIT extends AbstractIntegrationTestBase {

    private User deserializedUser;

    @Test
    public void name_is_deserialized_correctly() throws Exception {

        whenAValidUserIsDeserialized();

        Name name = deserializedUser.getName();

        assertThat(name.getFamilyName(), is(equalTo("Jensen")));
        assertThat(name.getFormatted(), is(equalTo("Ms. Barbara J Jensen III")));
        assertThat(name.getGivenName(), is(equalTo("Barbara")));
        assertThat(name.getHonorificPrefix(), is(nullValue()));
        assertThat(name.getHonorificSuffix(), is(nullValue()));
        assertThat(name.getMiddleName(), is(nullValue()));
    }

    @Test
    public void all_emails_are_transmitted() {

        whenAValidUserIsDeserialized();
        List<MultiValuedAttribute> emails = deserializedUser.getEmails();

        assertThat(emails, hasSize(1));
    }

    @Test
    public void emails_are_deserialized_correctly() throws Exception {

        whenAValidUserIsDeserialized();

        MultiValuedAttribute email = deserializedUser.getEmails().get(0);

        assertThat(email.getValue(), is(equalTo("bjensen@example.com")));
        assertThat(email.getType(), is(equalTo("work")));
    }

    @Test
    public void password_is_not_transmitted() throws Exception {
        whenAValidUserIsDeserialized();

        assertThat(deserializedUser.getPassword(), isEmptyString());
    }

    @Test(expected = UnauthorizedException.class)
    public void provide_an_invalid_access_token_raises_exception() throws Exception {
        givenAnInvalidAccessToken();

        whenAValidUserIsDeserialized();
        fail("Exception expected");
    }

    @Test(expected = UnauthorizedException.class)
    public void access_token_is_expired() throws Exception {
        givenAnAccessTokenForOneSecond();
        Thread.sleep(1000);
        whenAValidUserIsDeserialized();
        fail("Exception expected");
    }

    private void whenAValidUserIsDeserialized() {
        deserializedUser = oConnector.getUser(VALID_USER_ID, accessToken);
    }

}