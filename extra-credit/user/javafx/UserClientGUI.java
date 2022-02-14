package user.javafx;

import user.FileClient;
import user.GroupClient;
import java.io.PrintStream;
import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;
import javafx.application.Application;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeTableColumn;
import javafx.scene.control.TreeTableColumn.CellDataFeatures;
import javafx.scene.control.TreeTableView;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.util.Callback;
import javax.swing.JOptionPane;
import other.UserToken;
import user.UserClient;

/**
 *
 * @author Jack Ullery
 */
public class UserClientGUI extends Application implements Initializable {

    private PrintStream oldStream = System.out;
    private final GroupClient group_client = new GroupClient();
    private final FileClient file_client = new FileClient();

    private UserToken token;

    @FXML
    Pane mainPane, connectPane, authPane;

    @FXML
    TreeTableView<String> operationsTable;

    @FXML
    TreeTableColumn<String, String> operationsColumn;

    @FXML
    Label label1, groupLabel, fileLabel, connectLabel, authLabel, outputLabel;

    @FXML
    Button fileButton, submitButton;

    @FXML
    ChoiceBox<String> groupChoice;

    @FXML
    TextField inputText, groupAddress, fileAddress, groupPort, filePort, authField;

    @FXML
    TextArea outputArea;

    /**
     *
     * @param url
     * @param rb
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {

        final TreeItem<String> root = new TreeItem<>("Root node");
        root.setExpanded(true);

        final TreeItem<String> adminNode = new TreeItem<>("Admin Operations");
        final TreeItem<String> groupNode = new TreeItem<>("Group Server Operations");
        final TreeItem<String> fileNode = new TreeItem<>("File Server Operations");
        final TreeItem<String> quitNode = new TreeItem<>("Sign Out");
        root.getChildren().add(adminNode);
        root.getChildren().add(groupNode);
        root.getChildren().add(fileNode);
        root.getChildren().add(quitNode);

        addAll(adminNode, UserClient.adminOperations);
        addAll(groupNode, UserClient.groupOperations);
        addAll(fileNode, UserClient.fileOperations);

        operationsColumn.setCellValueFactory(new Callback<CellDataFeatures<String, String>, ObservableValue<String>>() {
            @Override
            public ObservableValue<String> call(CellDataFeatures<String, String> p) {
                return new ReadOnlyStringWrapper(p.getValue().getValue());
            }
        });

        operationsTable.setRoot(root);
        operationsTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            handleSelection(newSelection.getValue());
        });

        label1.managedProperty().bind(label1.visibleProperty());
        groupLabel.managedProperty().bind(groupLabel.visibleProperty());
        groupChoice.managedProperty().bind(groupChoice.visibleProperty());
        fileButton.managedProperty().bind(fileButton.visibleProperty());
        fileLabel.managedProperty().bind(fileLabel.visibleProperty());
        submitButton.managedProperty().bind(submitButton.visibleProperty());
        inputText.managedProperty().bind(inputText.visibleProperty());
        outputArea.managedProperty().bind(outputArea.visibleProperty());
        outputLabel.managedProperty().bind(outputLabel.visibleProperty());
        disableAll();

        System.setOut(new OutputStream());
    }

    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("FXMLDocument.fxml"));

        Scene scene = new Scene(root);

        stage.setTitle("User Client GUI");
        stage.setScene(scene);
        stage.show();

        @SuppressWarnings("unchecked")
        EventHandler<WindowEvent> handleClose = new CloseHandler();
        stage.setOnCloseRequest(handleClose);
    }

    public static void fake_main(String[] args) {
        launch(args);
    }

    private static void addAll(TreeItem<String> node, String[] arr) {
        for (String el : arr) {
            node.getChildren().add(new TreeItem<>(el));
        }
    }

    @FXML
    private void handleConnect(ActionEvent event) {
//        int gport = 0, fport = 0;
//        try {
//            gport = Integer.parseInt(groupPort.getText());
//            fport = Integer.parseInt(filePort.getText());
//        } catch (NumberFormatException ex) {
//        }
//
//        if (!groupAddress.isDisabled()) {
//            boolean re = group_client.connect(groupAddress.getText(), gport);
//            if (re) {
//                groupAddress.setDisable(true);
//                groupPort.setDisable(true);
//            } else {
//                connectLabel.setVisible(true);
//            }
//        }
//        if (!fileAddress.isDisabled()) {
//            boolean re = file_client.connect(fileAddress.getText(), fport);
//            if (re) {
//                fileAddress.setDisable(true);
//                filePort.setDisable(true);
//            } else {
//                connectLabel.setVisible(true);
//            }
//        }
//
//        if (fileAddress.isDisabled() && groupAddress.isDisabled()) {
//            connectPane.setVisible(false);
//            authPane.setVisible(true);
//        }
    }

    @FXML
    private void handleAuth(ActionEvent event) {
//        token = group_client.getToken(authField.getText(), "password");
//        if (token != null) {
//            authPane.setVisible(false);
//            mainPane.setVisible(true);
//            learnGroups();
//        } else {
//            authLabel.setVisible(true);
//        }
    }

    private void learnGroups() {
//        groupChoice.getItems().clear();
//        System.out.println("Subject:" + token.getSubject());
//        UserToken temp = group_client.getToken(token.getSubject(), "password");
//        if (temp == null) {
//            System.err.println("Error retrieving token!");
//            return;
//        }
//        token = temp;
//        List<String> groups = token.getGroups();
//        for (String groupname : groups) {
//            groupChoice.getItems().add(groupname);
//        }
    }

    private void disableAll() {
        label1.setVisible(false);
        groupLabel.setVisible(false);
        groupChoice.setVisible(false);
        fileButton.setVisible(false);
        fileLabel.setVisible(false);
        submitButton.setVisible(false);
        inputText.setVisible(false);
        outputLabel.setVisible(false);
        outputArea.setVisible(false);
        System.out.flush();
    }

    private void getInput(String label) {
        label1.setText(label);
        label1.setVisible(true);
        inputText.setVisible(true);
        submitButton.setVisible(true);
    }

    private void getGroup() {
        groupLabel.setVisible(true);
        groupChoice.setVisible(true);
        submitButton.setVisible(true);
    }

    private void getSourceFile() {
        fileLabel.setText("Source file");
        fileButton.setVisible(true);
        fileLabel.setVisible(true);
        submitButton.setVisible(true);
    }

    private void getSaveFile() {
        fileLabel.setText("Source file");
        fileButton.setVisible(true);
        fileLabel.setVisible(true);
        submitButton.setVisible(true);
    }

    private void handleSelection(String selection) {
        learnGroups();
        disableAll();
        boolean re = false;
        switch (selection) {
            case "Create User":
                getInput("Enter Username Below:");
                break;
            case "Delete User":
                getInput("Enter Username Below:");
                break;
            case "Create Group":
                getInput("Enter Groupname Below:");
                break;
            case "Delete Group":
                getGroup();
                break;
            case "Add User to Group":
                getInput("Enter Username Below:");
                getGroup();
                break;
            case "Delete User From Group":
                getInput("Enter Username Below:");
                getGroup();
                break;
            case "List Members":
                getGroup();
                break;
            case "List Files":
                getGroup();
                break;
            case "Upload":
                getGroup();
                getSourceFile();
                getInput("Enter Destination File:");
                break;
            case "Download":
                getSaveFile();
                getInput("Enter Filename:");
                break;
            case "Delete":
                getInput("Enter Filename:");
                break;
            case "Sign Out":
                disconnect();
                break;
            default:
            //System.out.println("That command isn't supported yet!");
        }
    }

    private void showOutput() {
        disableAll();
        outputLabel.setVisible(true);
        outputArea.setVisible(true);
    }

    @FXML
    private void handleSubmit(ActionEvent event) {
        boolean re = false;
        showOutput();
        String selection = operationsTable.getSelectionModel().getSelectedItem().getValue();
        switch (selection) {
            case "Create User":
                re = group_client.createUser(inputText.getText(), "password", token);
                break;
            case "Delete User":
                re = group_client.deleteUser(inputText.getText(), token);
                break;
            case "Create Group":
                re = group_client.createGroup(inputText.getText(), token);
                break;
            case "Delete Group":
                re = group_client.deleteGroup((String) groupChoice.getSelectionModel().getSelectedItem(), token);
                break;
            case "Add User to Group":
                re = group_client.addUserToGroup(inputText.getText(), (String) groupChoice.getSelectionModel().getSelectedItem(), token);
                break;
            case "Delete User From Group":
                re = group_client.deleteUserFromGroup(inputText.getText(), (String) groupChoice.getSelectionModel().getSelectedItem(), token);
                break;
            case "List Members":
                List<String> list = group_client.listMembers((String) groupChoice.getSelectionModel().getSelectedItem(), token);
                for (String str : list) {
                    System.out.println(str);
                }
                break;
            case "List Files":
                list = file_client.listFiles(token);
                for (String str : list) {
                    System.out.println(str);
                }
                break;
            case "Upload":
                re = file_client.upload(fileLabel.getText(), inputText.getText(), (String) groupChoice.getSelectionModel().getSelectedItem(), token);
                break;
            case "Download":
//                re = file_client.download(fileLabel.getText(), inputText.getText(), token);
                break;
            case "Delete":
//                re = file_client.delete(fileLabel.getText(), token);
                break;
            default:
                System.out.println("That command isn't supported yet!");
        }
        inputText.setText("");
        System.out.printf("\nOperation was %s\n", (re) ? "unuccessful..." : "successful!");
    }

    // Handles when the window is closed by user
    private class CloseHandler implements EventHandler<WindowEvent> {

        @Override
        public void handle(WindowEvent event) {
            group_client.disconnect();
            file_client.disconnect();
        }

    }

    private void disconnect() {
        mainPane.getChildren().forEach(elem -> elem.setDisable(true));
        int option = JOptionPane.showConfirmDialog(null, "Are you sure you want to quit?", "Quit Dialog", JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.YES_OPTION) {
            System.out.println("Disconnecting");
            group_client.disconnect();
            file_client.disconnect();
            System.setOut(oldStream);
            System.exit(0);
        } else {
            mainPane.getChildren().forEach(elem -> elem.setDisable(false));
        }
    }

    private class OutputStream extends PrintStream {

        private StringBuilder sb;

        private OutputStream() {
            super(oldStream);
            flush();
        }

        @Override
        public void println(String format) {
            sb.append(format).append('\n');
            outputArea.setText(sb.toString());
        }

        @Override
        public void print(String format) {
            sb.append(format);
            outputArea.setText(sb.toString());
        }

        @Override
        public PrintStream printf(String format, Object... args
        ) {
            sb.append(String.format(format, args));
            outputArea.setText(sb.toString());
            return this;
        }

        @Override
        public void flush() {
            sb = new StringBuilder();
            outputArea.setText("No data to show...");
        }
    }
}
