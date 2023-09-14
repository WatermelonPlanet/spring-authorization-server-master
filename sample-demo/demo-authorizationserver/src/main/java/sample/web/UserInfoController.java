
package sample.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
@RestController
public class UserInfoController {

	@GetMapping("/user_info")
	public String login() {
		return "login";
	}

}
