package project;
public class StringUtil {

    
    private static String get_trailing_string(String main_str, int len_of_trailing_str) {
        /*Returns the trailing substring of length len_of_trailing_str from the main_str  */

		int initial = main_str.length() - len_of_trailing_str;

		return main_str.substring(initial);

	}

	private static String get_leading_string(String main_str, int len_of_trailing_str) {
        /*Returns the leading substring  */
		int initial = main_str.length() - len_of_trailing_str;

		return main_str.substring(0, initial);
	}
}
