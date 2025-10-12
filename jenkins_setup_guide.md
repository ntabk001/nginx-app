# Hướng dẫn cài đặt Jenkins, SonarQube với PostgreSQL 15 trên RHEL 8

## Mục lục
1. [Cài đặt Java 17](#cài-đặt-java-17)
2. [Cài đặt PostgreSQL 15](#cài-đặt-postgresql-15)
3. [Cài đặt Jenkins](#cài-đặt-jenkins)
4. [Cài đặt SonarQube](#cài-đặt-sonarqube)
5. [Tích hợp Jenkins với SonarQube](#tích-hợp-jenkins-với-sonarqube)
6. [Script tự động tạo Project Java](#script-tự-động-tạo-project-java)

---

## Cài đặt Java 17

```bash
#!/bin/bash

# Cài đặt Java 17
echo "=== CÀI ĐẶT JAVA 17 ==="
sudo dnf update -y
sudo dnf install -y wget curl

# Cài đặt Java 17
sudo dnf install -y java-17-openjdk-devel

# Kiểm tra version
echo "Java version:"
java -version
echo "Javac version:"
javac -version

# Thiết lập JAVA_HOME
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk' | sudo tee -a /etc/profile.d/java.sh
echo 'export PATH=$JAVA_HOME/bin:$PATH' | sudo tee -a /etc/profile.d/java.sh
source /etc/profile.d/java.sh

echo "✓ Java 17 installed successfully"
```

---

## Cài đặt PostgreSQL 15

```bash
#!/bin/bash

echo "=== CÀI ĐẶT POSTGRESQL 15 ==="

# Cài đặt PostgreSQL 15
sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
sudo dnf -qy module disable postgresql
sudo dnf install -y postgresql15-server postgresql15-contrib

# Khởi tạo database
sudo /usr/pgsql-15/bin/postgresql-15-setup initdb
sudo systemctl start postgresql-15
sudo systemctl enable postgresql-15

# Tạo database và user cho SonarQube
sudo -i -u postgres psql <<EOF
CREATE USER sonar WITH PASSWORD 'sonar123';
CREATE DATABASE sonarqube OWNER sonar;
GRANT ALL PRIVILEGES ON DATABASE sonarqube TO sonar;
\q
EOF

# Cấu hình PostgreSQL
sudo bash -c 'cat > /var/lib/pgsql/15/data/pg_hba.conf' <<'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    replication     all             ::1/128                 scram-sha-256
EOF

# Khởi động lại PostgreSQL
sudo systemctl restart postgresql-15

# Kiểm tra trạng thái
echo "PostgreSQL status:"
sudo systemctl status postgresql-15 --no-pager

echo "✓ PostgreSQL 15 installed and configured successfully"
```

---

## Cài đặt Jenkins

```bash
#!/bin/bash

echo "=== CÀI ĐẶT JENKINS ==="

# Thêm repository Jenkins
sudo wget -O /etc/yum.repos.d/jenkins.repo \
    https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key

# Cài đặt Jenkins
sudo dnf install -y jenkins

# Khởi động Jenkins
sudo systemctl daemon-reload
sudo systemctl enable jenkins
sudo systemctl start jenkins

# Mở firewall
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# Hiển thị mật khẩu ban đầu
echo "=== JENKINS INITIAL ADMIN PASSWORD ==="
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
echo ""
echo "=== TRUY CẬP JENKINS ==="
echo "URL: http://$(hostname -I | awk '{print $1}'):8080"
echo "Password: (sử dụng password phía trên)"

echo "✓ Jenkins installed successfully"
```

---

## Cài đặt SonarQube

```bash
#!/bin/bash

echo "=== CÀI ĐẶT SONARQUBE ==="

# Tạo user và group cho SonarQube
sudo groupadd sonarqube
sudo useradd -c "SonarQube" -d /opt/sonarqube -g sonarqube -s /bin/bash sonarqube

# Tải và cài đặt SonarQube
cd /opt
sudo wget -q https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-10.2.0.77647.zip
sudo dnf install -y unzip
sudo unzip -q sonarqube-10.2.0.77647.zip
sudo mv sonarqube-10.2.0.77647 sonarqube
sudo chown -R sonarqube:sonarqube /opt/sonarqube

# Cấu hình SonarQube
sudo -u sonarqube bash -c 'cat > /opt/sonarqube/conf/sonar.properties' <<'EOF'
sonar.jdbc.username=sonar
sonar.jdbc.password=sonar123
sonar.jdbc.url=jdbc:postgresql://localhost:5432/sonarqube

sonar.web.host=0.0.0.0
sonar.web.port=9000

sonar.search.javaOpts=-Xmx512m -Xms512m -XX:MaxDirectMemorySize=256m
sonar.ce.javaOpts=-Xmx512m -Xms128m
EOF

# Cấu hình system limits
sudo bash -c 'cat > /etc/security/limits.d/sonarqube.conf' <<'EOF'
sonarqube   -   nofile   65536
sonarqube   -   nproc    4096
EOF

# Tạo systemd service
sudo bash -c 'cat > /etc/systemd/system/sonarqube.service' <<'EOF'
[Unit]
Description=SonarQube service
After=syslog.target network.target postgresql-15.service

[Service]
Type=forking
User=sonarqube
Group=sonarqube
PermissionsStartOnly=true
ExecStart=/opt/sonarqube/bin/linux-x86-64/sonar.sh start
ExecStop=/opt/sonarqube/bin/linux-x86-64/sonar.sh stop
ExecReload=/opt/sonarqube/bin/linux-x86-64/sonar.sh restart
LimitNOFILE=65536
LimitNPROC=4096
TimeoutStartSec=60
TimeoutStopSec=60
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Cấp quyền và khởi động
sudo chmod 755 /opt/sonarqube/bin/linux-x86-64/sonar.sh
sudo systemctl daemon-reload
sudo systemctl enable sonarqube

# Kiểm tra cấu hình database trước khi khởi động
echo "Testing database connection..."
sudo -i -u postgres psql -d sonarqube -c "SELECT version();" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    sudo systemctl start sonarqube
else
    echo "❌ Database connection failed. Please check PostgreSQL configuration."
    exit 1
fi

# Mở firewall
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --reload

# Chờ SonarQube khởi động
echo "Waiting for SonarQube to start..."
sleep 30

# Kiểm tra trạng thái
echo "SonarQube status:"
sudo systemctl status sonarqube --no-pager

echo "=== TRUY CẬP SONARQUBE ==="
echo "URL: http://$(hostname -I | awk '{print $1}'):9000"
echo "Default credentials: admin/admin"

echo "✓ SonarQube installed successfully"
```

---

## Script tự động tạo Project Java

```bash
#!/bin/bash

echo "=== TẠO PROJECT JAVA MẪU ==="

# Tạo thư mục project
PROJECT_DIR="$HOME/java-demo-project"
mkdir -p $PROJECT_DIR/src/main/java/com/example/demo
mkdir -p $PROJECT_DIR/src/test/java/com/example/demo

# Tạo file pom.xml
cat > $PROJECT_DIR/pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>java-demo-project</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>Java Demo Project</name>
    <description>A simple Java project for SonarQube demonstration</description>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <sonar.core.codeCoveragePlugin>jacoco</sonar.core.codeCoveragePlugin>
        <junit.version>5.9.2</junit.version>
        <maven.compiler.plugin.version>3.11.0</maven.compiler.plugin.version>
        <jacoco.version>0.8.10</jacoco.version>
        <surefire.version>3.0.0</surefire.version>
        <sonar.maven.plugin.version>3.10.0.2594</sonar.maven.plugin.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-api</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-engine</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-params</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>${maven.compiler.plugin.version}</version>
                <configuration>
                    <source>17</source>
                    <target>17</target>
                </configuration>
            </plugin>
            
            <plugin>
                <groupId>org.jacoco</groupId>
                <artifactId>jacoco-maven-plugin</artifactId>
                <version>${jacoco.version}</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>prepare-agent</goal>
                        </goals>
                    </execution>
                    <execution>
                        <id>report</id>
                        <phase>prepare-package</phase>
                        <goals>
                            <goal>report</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
            
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>${surefire.version}</version>
                <configuration>
                    <useSystemClassLoader>false</useSystemClassLoader>
                </configuration>
            </plugin>

            <plugin>
                <groupId>org.sonarsource.scanner.maven</groupId>
                <artifactId>sonar-maven-plugin</artifactId>
                <version>${sonar.maven.plugin.version}</version>
            </plugin>
        </plugins>
    </build>
</project>
EOF

# Tạo file Calculator.java
cat > $PROJECT_DIR/src/main/java/com/example/demo/Calculator.java <<'EOF'
package com.example.demo;

import java.util.ArrayList;
import java.util.List;

/**
 * Calculator class with basic arithmetic operations and mathematical functions
 */
public class Calculator {
    
    /**
     * Add two numbers
     * @param a first number
     * @param b second number
     * @return sum of a and b
     */
    public int add(int a, int b) {
        return a + b;
    }
    
    /**
     * Subtract two numbers
     * @param a first number
     * @param b second number
     * @return difference of a and b
     */
    public int subtract(int a, int b) {
        return a - b;
    }
    
    /**
     * Multiply two numbers
     * @param a first number
     * @param b second number
     * @return product of a and b
     */
    public int multiply(int a, int b) {
        return a * b;
    }
    
    /**
     * Divide two numbers
     * @param a dividend
     * @param b divisor
     * @return quotient of a divided by b
     * @throws ArithmeticException if divisor is zero
     */
    public double divide(int a, int b) {
        if (b == 0) {
            throw new ArithmeticException("Division by zero is not allowed");
        }
        return (double) a / b;
    }
    
    /**
     * Calculate power of a number
     * @param base the base number
     * @param exponent the exponent
     * @return base raised to the power of exponent
     */
    public double power(double base, double exponent) {
        return Math.pow(base, exponent);
    }
    
    /**
     * Calculate square root of a number
     * @param number the number
     * @return square root of the number
     * @throws IllegalArgumentException if number is negative
     */
    public double squareRoot(double number) {
        if (number < 0) {
            throw new IllegalArgumentException("Cannot calculate square root of negative number");
        }
        return Math.sqrt(number);
    }
    
    /**
     * Check if number is prime
     * @param number the number to check
     * @return true if number is prime, false otherwise
     */
    public boolean isPrime(int number) {
        if (number <= 1) {
            return false;
        }
        if (number == 2) {
            return true;
        }
        if (number % 2 == 0) {
            return false;
        }
        for (int i = 3; i <= Math.sqrt(number); i += 2) {
            if (number % i == 0) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Calculate factorial of a number
     * @param n the number
     * @return factorial of n
     * @throws IllegalArgumentException if n is negative
     */
    public long factorial(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("Factorial is not defined for negative numbers");
        }
        if (n == 0 || n == 1) {
            return 1;
        }
        long result = 1;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }
    
    /**
     * Find maximum number in an array
     * @param numbers array of numbers
     * @return maximum number
     * @throws IllegalArgumentException if array is null or empty
     */
    public int findMax(int[] numbers) {
        if (numbers == null || numbers.length == 0) {
            throw new IllegalArgumentException("Array cannot be null or empty");
        }
        int max = numbers[0];
        for (int i = 1; i < numbers.length; i++) {
            if (numbers[i] > max) {
                max = numbers[i];
            }
        }
        return max;
    }
    
    /**
     * Find minimum number in an array
     * @param numbers array of numbers
     * @return minimum number
     * @throws IllegalArgumentException if array is null or empty
     */
    public int findMin(int[] numbers) {
        if (numbers == null || numbers.length == 0) {
            throw new IllegalArgumentException("Array cannot be null or empty");
        }
        int min = numbers[0];
        for (int i = 1; i < numbers.length; i++) {
            if (numbers[i] < min) {
                min = numbers[i];
            }
        }
        return min;
    }
    
    /**
     * Calculate average of numbers in an array
     * @param numbers array of numbers
     * @return average value
     * @throws IllegalArgumentException if array is null or empty
     */
    public double calculateAverage(int[] numbers) {
        if (numbers == null || numbers.length == 0) {
            throw new IllegalArgumentException("Array cannot be null or empty");
        }
        int sum = 0;
        for (int number : numbers) {
            sum += number;
        }
        return (double) sum / numbers.length;
    }
    
    /**
     * Get Fibonacci sequence up to n numbers
     * @param n number of Fibonacci sequence elements
     * @return list of Fibonacci numbers
     * @throws IllegalArgumentException if n is negative
     */
    public List<Long> getFibonacciSequence(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("Number of elements cannot be negative");
        }
        List<Long> fibonacci = new ArrayList<>();
        if (n >= 1) {
            fibonacci.add(0L);
        }
        if (n >= 2) {
            fibonacci.add(1L);
        }
        for (int i = 2; i < n; i++) {
            long next = fibonacci.get(i - 1) + fibonacci.get(i - 2);
            fibonacci.add(next);
        }
        return fibonacci;
    }
}
EOF

# Tạo file StringUtils.java
cat > $PROJECT_DIR/src/main/java/com/example/demo/StringUtils.java <<'EOF'
package com.example.demo;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for string operations and manipulations
 */
public class StringUtils {
    
    /**
     * Reverse a string
     * @param input the string to reverse
     * @return reversed string, or null if input is null
     */
    public String reverse(String input) {
        if (input == null) {
            return null;
        }
        return new StringBuilder(input).reverse().toString();
    }
    
    /**
     * Check if string is palindrome
     * @param input the string to check
     * @return true if string is palindrome, false otherwise
     */
    public boolean isPalindrome(String input) {
        if (input == null) {
            return false;
        }
        String cleaned = input.replaceAll("[^a-zA-Z0-9]", "").toLowerCase();
        String reversed = reverse(cleaned);
        return cleaned.equals(reversed);
    }
    
    /**
     * Count vowels in a string
     * @param input the string to analyze
     * @return number of vowels in the string
     */
    public int countVowels(String input) {
        if (input == null || input.isEmpty()) {
            return 0;
        }
        int count = 0;
        String vowels = "aeiouAEIOU";
        for (char c : input.toCharArray()) {
            if (vowels.indexOf(c) != -1) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Count consonants in a string
     * @param input the string to analyze
     * @return number of consonants in the string
     */
    public int countConsonants(String input) {
        if (input == null || input.isEmpty()) {
            return 0;
        }
        int count = 0;
        String consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
        for (char c : input.toCharArray()) {
            if (consonants.indexOf(c) != -1) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Convert string to title case
     * @param input the string to convert
     * @return string in title case
     */
    public String toTitleCase(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String[] words = input.split("\\s+");
        StringBuilder result = new StringBuilder();
        for (String word : words) {
            if (!word.isEmpty()) {
                result.append(Character.toUpperCase(word.charAt(0)))
                      .append(word.substring(1).toLowerCase())
                      .append(" ");
            }
        }
        return result.toString().trim();
    }
    
    /**
     * Remove all whitespace from string
     * @param input the string to process
     * @return string without whitespace
     */
    public String removeWhitespace(String input) {
        if (input == null) {
            return null;
        }
        return input.replaceAll("\\s+", "");
    }
    
    /**
     * Count word frequency in a string
     * @param input the string to analyze
     * @return map of words and their frequencies
     */
    public Map<String, Integer> countWordFrequency(String input) {
        Map<String, Integer> frequencyMap = new HashMap<>();
        if (input == null || input.isEmpty()) {
            return frequencyMap;
        }
        String[] words = input.toLowerCase().split("\\W+");
        for (String word : words) {
            if (!word.isEmpty()) {
                frequencyMap.put(word, frequencyMap.getOrDefault(word, 0) + 1);
            }
        }
        return frequencyMap;
    }
    
    /**
     * Check if string contains only digits
     * @param input the string to check
     * @return true if string contains only digits, false otherwise
     */
    public boolean isNumeric(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return input.matches("\\d+");
    }
    
    /**
     * Capitalize first letter of string
     * @param input the string to capitalize
     * @return string with first letter capitalized
     */
    public String capitalizeFirst(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        return Character.toUpperCase(input.charAt(0)) + input.substring(1);
    }
    
    /**
     * Count occurrences of a substring in a string
     * @param input the main string
     * @param substring the substring to count
     * @return number of occurrences
     */
    public int countOccurrences(String input, String substring) {
        if (input == null || substring == null || substring.isEmpty()) {
            return 0;
        }
        int count = 0;
        int index = 0;
        while ((index = input.indexOf(substring, index)) != -1) {
            count++;
            index += substring.length();
        }
        return count;
    }
}
EOF

# Tạo file CalculatorTest.java
cat > $PROJECT_DIR/src/test/java/com/example/demo/CalculatorTest.java <<'EOF'
package com.example.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Calculator Tests")
class CalculatorTest {
    
    private Calculator calculator;
    
    @BeforeEach
    void setUp() {
        calculator = new Calculator();
    }
    
    @Test
    @DisplayName("Test addition with positive numbers")
    void testAddPositiveNumbers() {
        assertEquals(5, calculator.add(2, 3));
        assertEquals(10, calculator.add(5, 5));
    }
    
    @Test
    @DisplayName("Test addition with negative numbers")
    void testAddNegativeNumbers() {
        assertEquals(0, calculator.add(-2, 2));
        assertEquals(-5, calculator.add(-2, -3));
    }
    
    @ParameterizedTest
    @CsvSource({
        "5, 3, 2",
        "0, 5, 5",
        "-5, 0, 5"
    })
    @DisplayName("Test subtraction with various inputs")
    void testSubtract(int expected, int a, int b) {
        assertEquals(expected, calculator.subtract(a, b));
    }
    
    @Test
    @DisplayName("Test multiplication")
    void testMultiply() {
        assertEquals(6, calculator.multiply(2, 3));
        assertEquals(0, calculator.multiply(5, 0));
        assertEquals(-6, calculator.multiply(2, -3));
    }
    
    @Test
    @DisplayName("Test division with valid inputs")
    void testDivideValid() {
        assertEquals(2.0, calculator.divide(6, 3));
        assertEquals(2.5, calculator.divide(5, 2));
        assertEquals(-2.0, calculator.divide(-6, 3));
    }
    
    @Test
    @DisplayName("Test division by zero")
    void testDivideByZero() {
        assertThrows(ArithmeticException.class, () -> calculator.divide(5, 0));
    }
    
    @Test
    @DisplayName("Test power calculation")
    void testPower() {
        assertEquals(8.0, calculator.power(2, 3));
        assertEquals(1.0, calculator.power(5, 0));
        assertEquals(0.25, calculator.power(2, -2));
    }
    
    @Test
    @DisplayName("Test square root with valid inputs")
    void testSquareRootValid() {
        assertEquals(2.0, calculator.squareRoot(4));
        assertEquals(3.0, calculator.squareRoot(9));
    }
    
    @Test
    @DisplayName("Test square root with negative input")
    void testSquareRootNegative() {
        assertThrows(IllegalArgumentException.class, () -> calculator.squareRoot(-4));
    }
    
    @ParameterizedTest
    @ValueSource(ints = {2, 3, 5, 7, 11, 13, 17, 19})
    @DisplayName("Test prime numbers")
    void testIsPrimeWithPrimes(int number) {
        assertTrue(calculator.isPrime(number));
    }
    
    @ParameterizedTest
    @ValueSource(ints = {1, 4, 6, 8, 9, 10, 12, 15})
    @DisplayName("Test non-prime numbers")
    void testIsPrimeWithNonPrimes(int number) {
        assertFalse(calculator.isPrime(number));
    }
    
    @Test
    @DisplayName("Test factorial with valid inputs")
    void testFactorialValid() {
        assertEquals(1, calculator.factorial(0));
        assertEquals(1, calculator.factorial(1));
        assertEquals(120, calculator.factorial(5));
        assertEquals(3628800, calculator.factorial(10));
    }
    
    @Test
    @DisplayName("Test factorial with negative input")
    void testFactorialNegative() {
        assertThrows(IllegalArgumentException.class, () -> calculator.factorial(-1));
    }
    
    @Test
    @DisplayName("Test finding maximum in array")
    void testFindMax() {
        assertEquals(10, calculator.findMax(new int[]{1, 5, 10, 3, 8}));
        assertEquals(-1, calculator.findMax(new int[]{-5, -3, -1, -10}));
        assertEquals(5, calculator.findMax(new int[]{5}));
    }
    
    @Test
    @DisplayName("Test finding maximum in empty array")
    void testFindMaxEmptyArray() {
        assertThrows(IllegalArgumentException.class, () -> calculator.findMax(new int[]{}));
    }
    
    @Test
    @DisplayName("Test finding minimum in array")
    void testFindMin() {
        assertEquals(1, calculator.findMin(new int[]{5, 1, 10, 3, 8}));
        assertEquals(-10, calculator.findMin(new int[]{-5, -3, -1, -10}));
    }
    
    @Test
    @DisplayName("Test calculating average")
    void testCalculateAverage() {
        assertEquals(5.0, calculator.calculateAverage(new int[]{2, 4, 6, 8}));
        assertEquals(0.0, calculator.calculateAverage(new int[]{-2, 0, 2}));
    }
    
    @Test
    @DisplayName("Test Fibonacci sequence generation")
    void testFibonacciSequence() {
        List<Long> fib10 = calculator.getFibonacciSequence(10);
        assertArrayEquals(new Long[]{0L, 1L, 1L, 2L, 3L, 5L, 8L, 13L, 21L, 34L}, 
                         fib10.toArray(new Long[0]));
        
        List<Long> fib1 = calculator.getFibonacciSequence(1);
        assertArrayEquals(new Long[]{0L}, fib1.toArray(new Long[0]));
        
        List<Long> fib2 = calculator.getFibonacciSequence(2);
        assertArrayEquals(new Long[]{0L, 1L}, fib2.toArray(new Long[0]));
    }
    
    @Test
    @DisplayName("Test Fibonacci sequence with negative input")
    void testFibonacciSequenceNegative() {
        assertThrows(IllegalArgumentException.class, () -> calculator.getFibonacciSequence(-5));
    }
}
EOF

# Tạo file StringUtilsTest.java
cat > $PROJECT_DIR/src/test/java/com/example/demo/StringUtilsTest.java <<'EOF'
package com.example.demo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("StringUtils Tests")
class StringUtilsTest {
    
    private StringUtils stringUtils;
    
    @BeforeEach
    void setUp() {
        stringUtils = new StringUtils();
    }
    
    @Test
    @DisplayName("Test string reversal")
    void testReverse() {
        assertEquals("cba", stringUtils.reverse("abc"));
        assertEquals("", stringUtils.reverse(""));
        assertEquals("123", stringUtils.reverse("321"));
    }
    
    @Test
    @DisplayName("Test string reversal with null input")
    void testReverseNull() {
        assertNull(stringUtils.reverse(null));
    }
    
    @ParameterizedTest
    @ValueSource(strings = {"madam", "racecar", "A man a plan a canal Panama", "12321"})
    @DisplayName("Test palindrome strings")
    void testIsPalindromeWithPalindromes(String input) {
        assertTrue(stringUtils.isPalindrome(input));
    }
    
    @ParameterizedTest
    @ValueSource(strings = {"hello", "world", "java", "test"})
    @DisplayName("Test non-palindrome strings")
    void testIsPalindromeWithNonPalindromes(String input) {
        assertFalse(stringUtils.isPalindrome(input));
    }
    
    @Test
    @DisplayName("Test palindrome with null input")
    void testIsPalindromeNull() {
        assertFalse(stringUtils.isPalindrome(null));
    }
    
    @ParameterizedTest
    @CsvSource({
        "'Hello World', 3",
        "'AEIOU', 5",
        "'BCDFG', 0",
        "'Test String 123', 2",
        "'', 0"
    })
    @DisplayName("Test vowel counting")
    void testCountVowels(String input, int expectedCount) {
        assertEquals(expectedCount, stringUtils.countVowels(input));
    }
    
    @Test
    @DisplayName("Test vowel counting with null input")
    void testCountVowelsNull() {
        assertEquals(0, stringUtils.countVowels(null));
    }
    
    @Test
    @DisplayName("Test consonant counting")
    void testCountConsonants() {
        assertEquals(7, stringUtils.countConsonants("Hello World"));
        assertEquals(0, stringUtils.countConsonants("AEIOU"));
        assertEquals(5, stringUtils.countConsonants("BCDFG"));
    }
    
    @Test
    @DisplayName("Test title case conversion")
    void testToTitleCase() {
        assertEquals("Hello World", stringUtils.toTitleCase("hello world"));
        assertEquals("Java Programming", stringUtils.toTitleCase("JAVA PROGRAMMING"));
        assertEquals("A Short Story", stringUtils.toTitleCase("a short story"));
    }
    
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Test title case with null and empty input")
    void testToTitleCaseWithNullAndEmpty(String input) {
        assertEquals(input, stringUtils.toTitleCase(input));
    }
    
    @Test
    @DisplayName("Test whitespace removal")
    void testRemoveWhitespace() {
        assertEquals("HelloWorld", stringUtils.removeWhitespace("Hello World"));
        assertEquals("TestString", stringUtils.removeWhitespace("Test String"));
        assertEquals("123", stringUtils.removeWhitespace("1 2 3"));
    }
    
    @Test
    @DisplayName("Test word frequency counting")
    void testCountWordFrequency() {
        String input = "hello world hello java world test";
        Map<String, Integer> frequency = stringUtils.countWordFrequency(input);
        
        assertEquals(2, frequency.get("hello"));
        assertEquals(2, frequency.get("world"));
        assertEquals(1, frequency.get("java"));
        assertEquals(1, frequency.get("test"));
    }
    
    @ParameterizedTest
    @ValueSource(strings = {"123", "0", "9999"})
    @DisplayName("Test numeric strings")
    void testIsNumericWithNumbers(String input) {
        assertTrue(stringUtils.isNumeric(input));
    }
    
    @ParameterizedTest
    @ValueSource(strings = {"123a", "12.3", "test", "123 "})
    @DisplayName("Test non-numeric strings")
    void testIsNumericWithNonNumbers(String input) {
        assertFalse(stringUtils.isNumeric(input));
    }
    
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Test numeric check with null and empty input")
    void testIsNumericWithNullAndEmpty(String input) {
        assertFalse(stringUtils.isNumeric(input));
    }
    
    @Test
    @DisplayName("Test first letter capitalization")
    void testCapitalizeFirst() {
        assertEquals("Hello", stringUtils.capitalizeFirst("hello"));
        assertEquals("Java", stringUtils.capitalizeFirst("java"));
        assertEquals("A", stringUtils.capitalizeFirst("a"));
    }
    
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Test capitalization with null and empty input")
    void testCapitalizeFirstWithNullAndEmpty(String input) {
        assertEquals(input, stringUtils.capitalizeFirst(input));
    }
    
    @Test
    @DisplayName("Test substring occurrence counting")
    void testCountOccurrences() {
        assertEquals(2, stringUtils.countOccurrences("hello hello world", "hello"));
        assertEquals(3, stringUtils.countOccurrences("ababab", "ab"));
        assertEquals(0, stringUtils.countOccurrences("test", "java"));
    }
    
    @Test
    @DisplayName("Test substring occurrence with null inputs")
    void testCountOccurrencesWithNull() {
        assertEquals(0, stringUtils.countOccurrences(null, "test"));
        assertEquals(0, stringUtils.countOccurrences("test", null));
        assertEquals(0, stringUtils.countOccurrences("test", ""));
    }
}
EOF

# Tạo file Jenkinsfile
cat > $PROJECT_DIR/Jenkinsfile <<'EOF'
pipeline {
    agent any
    
    tools {
        jdk 'jdk17'
        maven 'maven3'
    }
    
    environment {
        SONAR_SCANNER_HOME = tool 'SonarScanner'
        SONAR_HOST_URL = 'http://localhost:9000'
    }
    
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/your-username/java-demo-project.git'
            }
        }
        
        stage('Build') {
            steps {
                sh 'mvn clean compile'
            }
        }
        
        stage('Unit Tests') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                    jacoco(
                        execPattern: 'target/jacoco.exec',
                        classPattern: 'target/classes',
                        sourcePattern: 'src/main/java'
                    )
                }
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                    mvn sonar:sonar \
                    -Dsonar.projectKey=java-demo-project \
                    -Dsonar.projectName="Java Demo Project" \
                    -Dsonar.host.url=$SONAR_HOST_URL \
                    -Dsonar.java.binaries=target/classes \
                    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                    -Dsonar.coverage.exclusions=**/test/** \
                    -Dsonar.sourceEncoding=UTF-8
                    '''
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Package') {
            steps {
                sh 'mvn package -DskipTests'
                archiveArtifacts 'target/*.jar'
            }
        }
        
        stage('Deploy') {
            when {
                expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
            }
            steps {
                echo 'Deploying application...'
                sh '''
                echo "Application packaged successfully!"
                echo "JAR file: target/java-demo-project-1.0.0.jar"
                echo "Deployment to server would happen here..."
                '''
            }
        }
    }
    
    post {
        always {
            emailext (
                subject: "Build ${currentBuild.result ?: 'SUCCESS'}: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                Build Result: ${currentBuild.result ?: 'SUCCESS'}
                Project: ${env.JOB_NAME}
                Build Number: ${env.BUILD_NUMBER}
                Console Output: ${env.BUILD_URL}console
                
                SonarQube Analysis: ${SONAR_HOST_URL}/dashboard?id=java-demo-project
                
                Test Results: ${env.BUILD_URL}testReport/
                """,
                to: "dev-team@company.com"
            )
        }
        failure {
            echo "Pipeline failed - check the logs for details"
        }
        success {
            echo "Pipeline completed successfully!"
            sh 'echo "Build and quality checks passed. Ready for deployment."'
        }
    }
}
EOF

# Tạo file sonar-project.properties
cat > $PROJECT_DIR/sonar-project.properties <<'EOF'
sonar.projectKey=java-demo-project
sonar.projectName=Java Demo Project
sonar.projectVersion=1.0.0

sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.java.binaries=target/classes
sonar.java.libraries=target/**/*.jar

sonar.sourceEncoding=UTF-8
sonar.java.source=17

sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
sonar.coverage.exclusions=**/test/**,**/generated-*/**

sonar.junit.reportPaths=target/surefire-reports
sonar.surefire.reportsPath=target/surefire-reports

sonar.cpd.exclusions=**/test/**
sonar.scm.disabled=true
EOF

# Tạo README file
cat > $PROJECT_DIR/README.md <<'EOF'
# Java Demo Project

A comprehensive Java project demonstrating CI/CD integration with Jenkins and SonarQube.

## Project Structure

```
java-demo-project/
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── example/
│   │               └── demo/
│   │                   ├── Calculator.java
│   │                   └── StringUtils.java
│   └── test/
│       └── java/
│           └── com/
│               └── example/
│                   └── demo/
│                       ├── CalculatorTest.java
│                       └── StringUtilsTest.java
├── Jenkinsfile
├── sonar-project.properties
└── pom.xml
```

## Features

- **Calculator**: Mathematical operations including arithmetic, prime checks, Fibonacci sequence
- **StringUtils**: String manipulation utilities including palindrome checks, word frequency analysis
- **Comprehensive Testing**: JUnit 5 tests with parameterized tests and assertions
- **Code Coverage**: JaCoCo integration for test coverage reporting
- **Quality Gates**: SonarQube integration for code quality checks

## Prerequisites

- Java 17
- Maven 3.6+
- Jenkins with SonarQube Scanner
- SonarQube Server

## Build and Test

```bash
mvn clean compile
mvn test
mvn sonar:sonar -Dsonar.host.url=http://sonarqube-server:9000
```

## Jenkins Pipeline

The project includes a Jenkinsfile that defines a complete CI/CD pipeline with:
- Code checkout
- Compilation
- Unit testing with coverage
- SonarQube analysis
- Quality gate checks
- Artifact packaging

## SonarQube Analysis

The project is configured for SonarQube analysis with:
- Code coverage reporting
- Quality gate integration
- Duplicate code detection
- Code smell analysis
- Security vulnerability scanning
EOF

# Tạo script build và test
cat > $PROJECT_DIR/build.sh <<'EOF'
#!/bin/bash

echo "=== BUILDING JAVA DEMO PROJECT ==="

# Clean and compile
echo "1. Cleaning and compiling..."
mvn clean compile

if [ $? -eq 0 ]; then
    echo "✓ Compilation successful"
else
    echo "❌ Compilation failed"
    exit 1
fi

# Run tests
echo "2. Running tests..."
mvn test

if [ $? -eq 0 ]; then
    echo "✓ Tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi

# Generate coverage report
echo "3. Generating coverage report..."
mvn jacoco:report

# Package application
echo "4. Packaging application..."
mvn package -DskipTests

if [ $? -eq 0 ]; then
    echo "✓ Packaging successful"
    echo "JAR file: target/java-demo-project-1.0.0.jar"
else
    echo "❌ Packaging failed"
    exit 1
fi

echo "=== BUILD COMPLETED SUCCESSFULLY ==="
EOF

chmod +x $PROJECT_DIR/build.sh

echo "✓ Java project created successfully at: $PROJECT_DIR"
echo ""
echo "=== PROJECT SUMMARY ==="
echo "Main classes:"
echo "  - Calculator.java (Mathematical operations)"
echo "  - StringUtils.java (String utilities)"
echo "Test classes:"
echo "  - CalculatorTest.java (Comprehensive unit tests)"
echo "  - StringUtilsTest.java (String utility tests)"
echo "Configuration files:"
echo "  - Jenkinsfile (CI/CD pipeline)"
echo "  - sonar-project.properties (SonarQube config)"
echo "  - pom.xml (Maven build config)"
echo ""
echo "To build and test:"
echo "  cd $PROJECT_DIR"
echo "  ./build.sh"
echo ""
echo "To initialize git repository:"
echo "  cd $PROJECT_DIR && git init && git add . && git commit -m 'Initial commit'"
```

## Script chạy toàn bộ quá trình

Tạo file `setup-complete.sh` để chạy toàn bộ quá trình cài đặt:

```bash
#!/bin/bash

echo "=== COMPLETE SETUP SCRIPT ==="
echo "This script will install all components and create the Java project"

# Chạy các script theo thứ tự
./install-java17.sh
./install-postgresql15.sh
./install-jenkins.sh
./install-sonarqube.sh
./create-java-project.sh

echo ""
echo "=== SETUP COMPLETED ==="
echo "Components installed:"
echo "✓ Java 17"
echo "✓ PostgreSQL 15"
echo "✓ Jenkins (port 8080)"
echo "✓ SonarQube (port 9000)"
echo "✓ Java demo project"
echo ""
echo "Access URLs:"
echo "Jenkins: http://$(hostname -I | awk '{print $1}'):8080"
echo "SonarQube: http://$(hostname -I | awk '{print $1}'):9000"
echo "Java project: $HOME/java-demo-project"
```

## Hướng dẫn sử dụng

### Bước 1: Tạo các script file
```bash
# Tạo các script file riêng biệt
nano install-java17.sh
# Copy nội dung script Java 17 và save

nano install-postgresql15.sh
# Copy nội dung script PostgreSQL 15 và save

nano install-jenkins.sh
# Copy nội dung script Jenkins và save

nano install-sonarqube.sh
# Copy nội dung script SonarQube và save

nano create-java-project.sh
# Copy nội dung script tạo project Java và save

nano setup-complete.sh
# Copy nội dung script complete và save
```

### Bước 2: Cấp quyền thực thi
```bash
chmod +x *.sh
```

### Bước 3: Chạy script hoàn chỉnh
```bash
./setup-complete.sh
```

### Bước 4: Cấu hình tích hợp

**Cấu hình Jenkins với SonarQube:**

1. Truy cập Jenkins: `http://your-server-ip:8080`
2. Cài đặt plugins:
   - SonarQube Scanner
   - Sonar Quality Gates
   - JaCoCo plugin

3. Cấu hình SonarQube server trong Jenkins:
   - Manage Jenkins → Configure System
   - SonarQube servers → Add SonarQube
   - Name: `SonarQube`
   - URL: `http://localhost:9000`
   - Token: Tạo token trong SonarQube

4. Cấu hình tools trong Jenkins:
   - JDK: `jdk17` → JAVA_HOME: `/usr/lib/jvm/java-17-openjdk`
   - Maven: `maven3` (install automatically)
   - SonarScanner: `SonarScanner` (install automatically)

## Troubleshooting

### Kiểm tra services
```bash
# Kiểm tra trạng thái các services
sudo systemctl status jenkins
sudo systemctl status sonarqube
sudo systemctl status postgresql-15

# Kiểm tra log
sudo tail -f /var/log/jenkins/jenkins.log
sudo tail -f /opt/sonarqube/logs/sonar.log
sudo tail -f /var/lib/pgsql/15/data/log/postgresql-*.log
```

### Vấn đề thường gặp

1. **SonarQube không khởi động**: Kiểm tra memory và database connection
2. **Jenkins không kết nối được SonarQube**: Kiểm tra token và URL
3. **Build failure**: Kiểm tra Java version và Maven configuration

---

Các script này sẽ tự động cài đặt toàn bộ môi trường và tạo một project Java đầy đủ với các tính năng phong phú để SonarQube có thể scan và phân tích code quality.