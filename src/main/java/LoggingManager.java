import org.apache.log4j.*;

/**
 * Created by andresmonroy on 5/2/14.
 */
public class LoggingManager {

	public static void initLogging(boolean showLogging){
		ConsoleAppender console = new ConsoleAppender(); //create appender
		//configure the appender
		String PATTERN = "%d [%p|%c|%C{1}] %m%n";
		console.setLayout(new PatternLayout(PATTERN));
		if (showLogging){
			console.setThreshold(Level.INFO);
		} else {
			console.setThreshold(Level.ERROR);
		}
		console.activateOptions();
		Logger.getRootLogger().addAppender(console);

//		FileAppender fa = new FileAppender();
//		fa.setName("FileLogger");
//		fa.setFile("mylog.log");
//		fa.setLayout(new PatternLayout("%d %-5p [%c{1}] %m%n"));
//		fa.setThreshold(Level.DEBUG);
//		fa.setAppend(true);
//		fa.activateOptions();
//
//		//add appender to any Logger (here is root)
//		Logger.getRootLogger().addAppender(fa);
	}
}
